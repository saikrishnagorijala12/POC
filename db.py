

from flask import Flask, jsonify, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime,timezone, timedelta
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'data.db')

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_PATH}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


# ---------- Models (fixed names, tables, timezone defaults) ----------
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class Client(db.Model):
    __tablename__ = 'client_keys'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    domo_client_id = db.Column(db.String(200), nullable=False)
    domo_client_secret = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationship: User.clients will give a list of Client objects
    user = db.relationship('User', backref=db.backref('clients', lazy=True))

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'domo_id': self.domo_client_id,
            'domo_secret': self.domo_client_secret,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class Embedded(db.Model):
    __tablename__ = 'embedded_pages'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    embed_page_id = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    user = db.relationship('User', backref=db.backref('embeds', lazy=True))

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'page_id': self.embed_page_id,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }



# -------------------------
# Routes
# -------------------------
@app.route('/')
def index():
    return jsonify({
        'message': 'Flask + SQLite demo. Use /init-db to create tables.'
    })

@app.route('/init-db', methods=['POST', 'GET'])
def init_db():
    """Create the SQLite database file and tables."""
    # Ensure directory exists
    os.makedirs(BASE_DIR, exist_ok=True)
    db.create_all()
    return jsonify({'message': 'Database initialized', 'db_path': DB_PATH})

@app.route('/add-user', methods=['POST'])
def add_user():
    data = request.get_json() or {}
    name = data.get('name')
    email = data.get('email')
    if not name or not email:
        return jsonify({'error': 'name and email are required'}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'email already exists'}), 400

    user = User(name=name, email=email)
    db.session.add(user)
    db.session.commit()
    return jsonify(user.to_dict()), 201


@app.route('/users', methods=['GET'])
def list_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return jsonify([u.to_dict() for u in users]), 200


@app.route('/add-client', methods=['POST'])
def add_client():
    """
    Expected JSON:
    {
      "email": "user@example.com",
      "client_id": "your-domo-client-id",
      "client_secret": "your-domo-client-secret"
    }
    """
    data = request.get_json() or {}
    email = data.get('email')
    domo_client_id = data.get('client_id')
    domo_client_secret = data.get('client_secret')

    if not email or not domo_client_id or not domo_client_secret:
        return jsonify({'error': 'email, client_id and client_secret are required'}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'user not found'}), 404

    existing = Client.query.filter_by(user_id=user.id, domo_client_id=domo_client_id).first()
    if existing:
        return jsonify({'error': 'this client_id is already registered for the user'}), 400

    client = Client(
        user_id=user.id,
        domo_client_id=domo_client_id,
        domo_client_secret=domo_client_secret
    )

    db.session.add(client)
    db.session.commit()

    return jsonify(client.to_dict()), 201



@app.route('/clients', methods=['GET'])
def list_clients():
    clients = Client.query.order_by(Client.created_at.desc()).all()
    return jsonify([c.to_dict() for c in clients]), 200


@app.route('/add-embed', methods=['POST'])
def add_embed():
    """
    Expected JSON:
    {
      "email": "user@example.com",
      "embed_page_id": "abc123"
    }
    """
    data = request.get_json() or {}
    email = data.get('email')
    embed_page_id = (data.get('embed_page_id') or '').strip()

    # Basic validation
    if not email or not embed_page_id:
        return jsonify({'error': 'email and embed_page_id are required'}), 400

    # Get user by email
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'user not found'}), 404

    # Optional: check if this embed already exists for this user
    existing = Embedded.query.filter_by(user_id=user.id, embed_page_id=embed_page_id).first()
    if existing:
        return jsonify({'error': 'this embed_page_id already exists for this user'}), 400

    # Create new embed record
    embed = Embedded(user_id=user.id, embed_page_id=embed_page_id)
    db.session.add(embed)
    db.session.commit()

    return jsonify(embed.to_dict()), 201



@app.route('/embeds', methods=['GET'])
def list_embeds():
    embeds = Embedded.query.order_by(Embedded.created_at.desc()).all()
    return jsonify([e.to_dict() for e in embeds]), 200

# -------------------------
# Run app
# -------------------------
if __name__ == '__main__':
    # Create DB file if not exists
    if not os.path.exists(DB_PATH):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    app.run(debug=True)
