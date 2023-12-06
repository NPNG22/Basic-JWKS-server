import os
import sqlite3
from flask import Flask, request, jsonify, g
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding
import datetime
import jwt
from cryptography.fernet import Fernet
from secrets import token_urlsafe
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Initialize the Flask app
app = Flask(__name__)

# Rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["10/second"],
    storage_uri="memory://",
)
# AES encryption key from the environment variable
ENCRYPTION_KEY = os.environ.get("NOT_MY_KEY")

# Initialize a password hasher
ph = PasswordHasher()

# Database initialization and utility functions

# Create the 'keys' table if it doesn't exist


def create_keys_table():
    with app.app_context():
        cursor = get_cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS keys (
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp TEXT NOT NULL
            )
        ''')
        get_db().commit()

# Create the 'auth_logs' table if it doesn't exist


def create_auth_logs_table():
    with app.app_context():
        logs_db = sqlite3.connect('auth_logs.db')
        cursor = logs_db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS auth_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_ip TEXT NOT NULL,
                request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        logs_db.commit()
        logs_db.close()

# Create the 'users' table if it doesn't exist


def create_users_table():
    with app.app_context():
        users_db = sqlite3.connect('users.db')
        cursor = users_db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT
            )
        ''')
        users_db.commit()
        users_db.close()


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect('totally_not_my_privateKeys.db')
        g.db.row_factory = sqlite3.Row
    return g.db


def get_cursor():
    return get_db().cursor()


def save_private_key_to_db(private_key, expiry):
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    cursor = get_cursor()
    cursor.execute('INSERT INTO keys (key, exp) VALUES (?, ?)',
                   (pem_private_key, expiry.strftime('%Y-%m-%d %H:%M:%S.%f'))
                   )
    get_db().commit()


def generate_and_save_rsa_key(expiry=None):
    if expiry is None:
        expiry = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    save_private_key_to_db(private_key, expiry)
    return private_key


def rsa_to_jwks(private_key, kid, expiry):
    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode('utf-8')
    jwk = {
        "kid": kid,
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "n": public_key.public_numbers().n,
        "e": public_key.public_numbers().e,
        "exp": expiry.strftime('%Y-%m-%d %H:%M:%S.%f'),
    }
    return jwk


def get_active_keys():
    current_time = datetime.datetime.utcnow()
    with app.app_context():
        cursor = get_cursor()
        cursor.execute(
            'SELECT key, exp FROM keys WHERE exp > ?', (current_time.strftime(
                '%Y-%m-%d %H:%M:%S.%f'),)
        )
        rows = cursor.fetchall()
        active_keys = []
        for row in rows:
            private_key = serialization.load_pem_private_key(
                row[0], password=None
            )
            active_keys.append({
                "kid": None,
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "n": private_key.private_numbers().public_numbers.n,
                "e": private_key.private_numbers().public_numbers.e,
                "exp": row[1],
            })
        return active_keys


def log_auth_request(request_ip, user_id):
    with app.app_context():
        logs_db = sqlite3.connect('auth_logs.db')
        cursor = logs_db.cursor()
        cursor.execute('INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)',
                       (request_ip, user_id)
                       )
        logs_db.commit()
        logs_db.close()


# Create the 'keys' table if it doesn't exist
create_keys_table()

# Create the 'auth_logs' table if it doesn't exist
create_auth_logs_table()

# Create the 'users' table if it doesn't exist
create_users_table()

# Retrieve a list of active keys from the database
keys = get_active_keys()

# Endpoint to generate and store a key that expires in 1 second


@app.route('/generate-key/1-second', methods=['POST'])
def generate_and_store_key_1_second():
    expiry = datetime.datetime.utcnow() + datetime.timedelta(seconds=1)
    private_key = generate_and_save_rsa_key(expiry)
    if expiry > datetime.datetime.utcnow():
        keys.append(rsa_to_jwks(private_key, None, expiry))
    return jsonify({"message": "Key generated and stored successfully"})

# Endpoint to generate and store a key that expires in 1 minute


@app.route('/generate-key/1-minute', methods=['POST'])
def generate_and_store_key_1_minute():
    expiry = datetime.datetime.utcnow() + datetime.timedelta(minutes=1)
    private_key = generate_and_save_rsa_key(expiry)
    if expiry > datetime.datetime.utcnow():
        keys.append(rsa_to_jwks(private_key, None, expiry))
    return jsonify({"message": "Key generated and stored successfully"})

# Endpoint to get the active keys


@app.route('/.well-known/jwks.json', methods=['GET'])
def get_jwks():
    current_time = datetime.datetime.utcnow()
    valid_keys = [key for key in keys if datetime.datetime.strptime(
        key["exp"], '%Y-%m-%d %H:%M:%S.%f') > current_time
    ]
    return jsonify({"keys": valid_keys})

# User registration endpoint


@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")

    # Generate a secure random password
    password = token_urlsafe(16)

    # Hash the password using Argon2
    password_hash = ph.hash(password)

    # Store user details and hashed password in the database
    with app.app_context():
        users_db = sqlite3.connect('users.db')
        cursor = users_db.cursor()
        cursor.execute('INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)',
                       (username, password_hash, email)
                       )
        users_db.commit()
        users_db.close()

    return jsonify({"password": password}), 200

# Authentication endpoint


@app.route('/auth', methods=['POST'])
@limiter.limit("10/second", override_defaults=False)
def authenticate():
    if request.authorization:
        username = request.authorization.username
        password = request.authorization.password
        expired = request.args.get('expired')
        with app.app_context():
            users_db = sqlite3.connect('users.db')
            cursor = users_db.cursor()
            cursor.execute(
                'SELECT id, password_hash FROM users WHERE username = ?', (
                    username,)
            )
            row = cursor.fetchone()
        if row:
            user_id, stored_password_hash = row
            try:
                # Verify the password using Argon2
                ph.verify(stored_password_hash, password)
                kid = "sample-key"
                expiry = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
                if expired:
                    expiry = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
                private_key = generate_and_save_rsa_key(expiry)
                jwk = rsa_to_jwks(private_key, kid, expiry)
                keys.append(jwk)
                payload = {
                    "sub": username,
                    "iat": datetime.datetime.utcnow(),
                    "exp": expiry.strftime('%Y-%m-%d %H:%M:%S.%f'),
                }
                token = jwt.encode(payload, private_key, algorithm="RS256")
                header = {
                    "kid": kid,
                    "alg": "RS256",
                    "typ": "JWT",
                }
                jwt_with_kid = jwt.encode(
                    payload, private_key, algorithm="RS256", headers=header
                )

                # Log successful authentication request
                # Log the request IP and user_id
                log_auth_request(request.remote_addr, user_id)

                return jsonify({"token": jwt_with_kid})

            except VerifyMismatchError:
                return jsonify({"error": "Authentication failed"}), 401

    return jsonify({"error": "Authentication failed"}), 401


if __name__ == '__main__':
    app.run(port=8080, threaded=False)
