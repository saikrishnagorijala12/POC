#!/usr/bin/env python3
"""
azure_to_domo_sync.py

Simple Azure AD -> Domo user sync (full/paged sync).
Safe defaults: DRY_RUN=1 prevents writes.
"""

import os
import time
import json
import logging
from typing import Dict, List, Optional

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("azure-domo-sync")

# Config from env
AZ_TENANT = os.getenv("AZURE_TENANT_ID", "4102faaf-7c01-4c91-8405-ddbfa449a4c4")
AZ_CLIENT = os.getenv("AZURE_CLIENT_ID","b61bea75-a7bb-4cf6-bd2d-ef2456643b07")
AZ_SECRET = os.getenv("AZURE_CLIENT_SECRET", ".0M8Q~TMnli9FIwTyrqdOHN8w2BoGlIgV7gFecse")
AZ_SCOPE = os.getenv("AZURE_SCOPE", "https://graph.microsoft.com/.default")
PAGE_SIZE = int(os.getenv("PAGE_SIZE", "50"))

DOMO_API_HOST = os.getenv("DOMO_API_HOST", "https://api.domo.com")
DOMO_CLIENT_ID = os.getenv("DOMO_CLIENT_ID" , "3d1c4a89-baa7-4f9a-8dc3-adbf0b153001")
DOMO_CLIENT_SECRET = os.getenv("DOMO_CLIENT_SECRET", "c21ea2d80a3d022557826a29b9e8cc84e2c87b6b1c399665e174d277798540d7")

# role mapping example:
# '{"AzureGroupNameOrId":"domoRoleId", "AnotherGroup":"roleId2"}'
DOMO_ROLE_MAPPING = json.loads(os.getenv("DOMO_ROLE_MAPPING_JSON", "{}"))
DRY_RUN = False
# os.getenv("DRY_RUN", "1") == "1"

if not (AZ_TENANT and AZ_CLIENT and AZ_SECRET and DOMO_CLIENT_ID and DOMO_CLIENT_SECRET):
    raise RuntimeError("Set AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, DOMO_CLIENT_ID, DOMO_CLIENT_SECRET")

# Simple in-process caches
_dom_oauth = {"token": None, "expires_at": 0}
# Azure token not cached globally since script may be short-lived
TIMEOUT = 10


def get_azure_access_token() -> str:
    # Client credentials flow for Microsoft Identity platform
    url = f"https://login.microsoftonline.com/{AZ_TENANT}/oauth2/v2.0/token"
    data = {
        "client_id": AZ_CLIENT,
        "scope": AZ_SCOPE,
        "client_secret": AZ_SECRET,
        "grant_type": "client_credentials",
    }
    r = requests.post(url, data=data, timeout=TIMEOUT)
    r.raise_for_status()
    return r.json()["access_token"]


def get_azure_users(access_token: str) -> List[Dict]:
    log.info("Fetching users from Azure AD")
    users = []
    url = f"https://graph.microsoft.com/v1.0/users?$top={PAGE_SIZE}&$select=id,displayName,givenName,surname,mail,userPrincipalName,accountEnabled"
    headers = {"Authorization": f"Bearer {access_token}"}
    while url:
        r = requests.get(url, headers=headers, timeout=TIMEOUT)
        r.raise_for_status()
        j = r.json()
        batch = j.get("value", [])
        users.extend(batch)
        log.info("Fetched %d users (total %d)", len(batch), len(users))
        url = j.get("@odata.nextLink")  # paging
    log.info("Total Azure users fetched: %d", len(users))
    return users


def get_domo_access_token() -> str:
    """
    Robust Domo token fetcher:
    - tries POST without scope, then with 'data user dashboard', then 'all'
    - logs Domo JSON error bodies to help debugging
    - caches token in _dom_oauth
    """
    now = time.time()
    if _dom_oauth.get("token") and _dom_oauth.get("expires_at", 0) > now + 5:
        return _dom_oauth["token"]

    token_url = f"{DOMO_API_HOST}/oauth/token"
    creds = f"{DOMO_CLIENT_ID}:{DOMO_CLIENT_SECRET}"
    b64 = __import__("base64").b64encode(creds.encode()).decode()
    headers = {"Authorization": f"Basic {b64}", "Accept": "application/json"}

    tried = []
    for scope_value in (None, "data user dashboard", "all"):
        tried.append(scope_value)
        data = {"grant_type": "client_credentials"}
        if scope_value:
            data["scope"] = scope_value

        try:
            r = requests.post(token_url, headers=headers, data=data, timeout=TIMEOUT)
        except Exception as e:
            log.error("Error contacting Domo token endpoint (scope=%s): %s", scope_value, e)
            continue

        if r.status_code == 200:
            j = r.json()
            token = j.get("access_token")
            expires_in = j.get("expires_in", 300)
            _dom_oauth["token"] = token
            _dom_oauth["expires_at"] = time.time() + int(expires_in)
            log.info("Got Domo access token (scope=%s), expires in %s sec", scope_value, expires_in)
            return token

        # not 200 — log JSON body or text
        try:
            body = r.json()
        except Exception:
            body = r.text or "<no body>"
        log.error("Domo token request failed (scope=%s): status=%s body=%s", scope_value, r.status_code, body)

    # nothing worked
    raise RuntimeError(f"Domo token request failed for scopes tried: {tried}")



def domo_find_user_by_email(domo_token: str, email: str) -> Optional[Dict]:
    """
    Reliable lookup:
    - Query /v1/users?email=... may return multiple results (or a support user first).
    - Iterate results and return the one whose 'email' equals the requested email (case-insensitive).
    - If none match exactly, return None.
    """
    if not email:
        return None

    url = f"{DOMO_API_HOST}/v1/users?email={requests.utils.quote(email)}"
    headers = {"Authorization": f"Bearer {domo_token}", "Accept": "application/json"}
    try:
        r = requests.get(url, headers=headers, timeout=TIMEOUT)
        data = r.json() if r.status_code == 200 else None
    except Exception as ex:
        log.warning("Domo lookup failed for email=%s: %s", email, ex)
        return None

    log.info("LOOKUP email='%s' domo response=%s", email, data)

    if not data:
        return None

    # If Domo returns a list, find exact match
    if isinstance(data, list):
        for u in data:
            u_email = (u.get("email") or "").lower()
            if u_email == email.lower():
                return u
        # not found exact match
        return None

    # If Domo returned dict with a user
    if isinstance(data, dict) and data.get("id"):
        # ensure match
        if (data.get("email") or "").lower() == email.lower():
            return data
        # dict but not matching email
        return None

    return None


def domo_update_user(domo_token: str, domo_user_id: str, data: Dict, existing_email: str = None) -> bool:
    """
    Update user. Domo requires email in update payload; include it.
    Pass existing_email (the email on the Domo user) to include if not present.
    """
    if DRY_RUN:
        # show full payload that would be sent, including email
        payload = dict(data)
        if "email" not in payload and existing_email:
            payload["email"] = existing_email
        log.info("[DRY RUN] Would update Domo user %s with %s", domo_user_id, payload)
        return True

    url = f"{DOMO_API_HOST}/v1/users/{domo_user_id}"
    payload = dict(data)
    if "email" not in payload:
        if existing_email:
            payload["email"] = existing_email
        else:
            log.error("No email available for update payload for user %s, aborting update", domo_user_id)
            return False

    headers = {"Authorization": f"Bearer {domo_token}", "Content-Type": "application/json"}
    r = requests.put(url, headers=headers, json=payload, timeout=TIMEOUT)
    if r.status_code in (200, 204):
        return True

    log.error("Failed to update Domo user %s: %s %s", domo_user_id, r.status_code, r.text)
    return False


def domo_create_user(domo_token: str, email: str, first: str, last: str, active: bool = True) -> Optional[Dict]:
    """
    Create user. Validate email and skip guest-style UPNs that Domo will reject.
    """
    # basic sanity: must contain '@' and a dot after @
    if not email or "@" not in email or "." not in email.split("@")[-1]:
        log.warning("Skipping create - suspicious email format: %s", email)
        return None

    # Guest accounts from AAD sometimes look like: user_hotmail.com#EXT#@tenant.onmicrosoft.com
    # These are not valid target emails for Domo. Prefer 'mail' or userPrincipalName where possible.
    if "#EXT#" in email or email.lower().endswith("onmicrosoft.com"):
        log.warning("Skipping create - looks like an external/guest UPN that may not map to real mailbox: %s", email)
        return None

    if DRY_RUN:
        log.info("[DRY RUN] Would create Domo user: %s (%s %s) active=%s", email, first, last, active)
        return {"email": email}
    url = f"{DOMO_API_HOST}/v1/users"
    payload = {
        "email": email,
        "firstName": first or "",
        "lastName": last or "",
        "isSuperUser": False,
        "isSsoUser": True,
        "active": bool(active),
    }
    headers = {"Authorization": f"Bearer {domo_token}", "Content-Type": "application/json"}
    r = requests.post(url, headers=headers, json=payload, timeout=TIMEOUT)
    if r.status_code in (200, 201):
        return r.json()
    else:
        log.error("Failed to create Domo user %s: %s %s", email, r.status_code, r.text)
        return None



# def domo_update_user(domo_token: str, domo_user_id: str, data: Dict) -> bool:
#     if DRY_RUN:
#         log.info("[DRY RUN] Would update Domo user %s with %s", domo_user_id, data)
#         return True
#     url = f"{DOMO_API_HOST}/v1/users/{domo_user_id}"
#     headers = {"Authorization": f"Bearer {domo_token}", "Content-Type": "application/json"}
#     r = requests.put(url, headers=headers, json=data, timeout=TIMEOUT)
#     if r.status_code in (200, 204):
#         return True
#     log.error("Failed to update Domo user %s: %s %s", domo_user_id, r.status_code, r.text)
#     return False


def domo_disable_user(domo_token: str, domo_user_id: str) -> bool:
    if DRY_RUN:
        log.info("[DRY RUN] Would disable Domo user %s", domo_user_id)
        return True
    # Some tenants expect PATCH fields; using PUT with active flag if API supports:
    url = f"{DOMO_API_HOST}/v1/users/{domo_user_id}"
    payload = {"active": False}
    headers = {"Authorization": f"Bearer {domo_token}", "Content-Type": "application/json"}
    r = requests.put(url, headers=headers, json=payload, timeout=TIMEOUT)
    if r.status_code in (200, 204):
        return True
    log.error("Failed to disable Domo user %s: %s %s", domo_user_id, r.status_code, r.text)
    return False


def sync():
    az_token = get_azure_access_token()
    az_users = get_azure_users(az_token)
    domo_token = get_domo_access_token()

    created = 0
    updated = 0
    disabled = 0

    for u in az_users:
        # determine email (prefer mail, fallback to userPrincipalName)
        email = u.get("mail") or u.get("userPrincipalName")
        if not email:
            log.warning("Skipping Azure user without email: %s", u.get("id"))
            continue
        first = u.get("givenName") or ""
        last = u.get("surname") or ""
        enabled = u.get("accountEnabled", True)

        domo_user = domo_find_user_by_email(domo_token, email)
        if not domo_user:
            res = domo_create_user(domo_token, email, first, last, active=enabled)
            if res:
                created += 1
        else:
            domo_id = str(domo_user.get("id") or domo_user.get("userId") or "")
            # Build update payload with fields you want to keep in sync
            update_payload = {}
            # Example: update first/last names if different
            if first and domo_user.get("firstName") != first:
                update_payload["firstName"] = first
            if last and domo_user.get("lastName") != last:
                update_payload["lastName"] = last
            # active flag
            if not enabled:
                # disable user in Domo
                if domo_disable_user(domo_token, domo_id):
                    disabled += 1
                    continue
            if update_payload:
                if domo_update_user(domo_token, domo_id, update_payload):
                    updated += 1

    log.info("Sync complete: created=%s updated=%s disabled=%s", created, updated, disabled)


if __name__ == "__main__":
    log.info("Starting Azure AD -> Domo sync (DRY_RUN=%s)", DRY_RUN)
    sync()
