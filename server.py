import os  # Import the 'os' module for working with the file system
import sqlite3  # Import the 'sqlite3' module for working with SQLite databases
from flask import Flask, request, jsonify, g  # Import Flask and related modules
# Import RSA encryption from cryptography
from cryptography.hazmat.primitives.asymmetric import rsa
# Import serialization functions
from cryptography.hazmat.primitives import serialization
# Import Encoding for serialization
from cryptography.hazmat.primitives.serialization import Encoding
import datetime  # Import the 'datetime' module for working with dates and times
import jwt  # Import the 'jwt' module for JSON Web Tokens (JWT)
import atexit  # Import 'atexit' to register cleanup function

app = Flask(__name__)  # Create a Flask application

# Function to get the database connection


def get_db():
    if 'db' not in g:
        # Connect to the SQLite database
        g.db = sqlite3.connect('totally_not_my_privateKeys.db')
        g.db.row_factory = sqlite3.Row  # Set row factory to return rows as dictionaries
    return g.db

# Function to get the cursor


def get_cursor():
    return get_db().cursor()  # Get a cursor for the database connection

# Create the 'keys' table if it doesn't exist


def create_keys_table():
    with app.app_context():  # Create an application context
        cursor = get_cursor()  # Get a cursor
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS keys (
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp TEXT NOT NULL  -- Store 'exp' as text
            )
        ''')  # SQL statement to create the 'keys' table if it doesn't exist
        get_db().commit()  # Commit the transaction

# Function to save a private key to the database


def save_private_key_to_db(private_key, expiry):
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )  # Serialize the private key to PEM format
    cursor = get_cursor()  # Get a cursor
    cursor.execute('INSERT INTO keys (key, exp) VALUES (?, ?)',
                   (pem_private_key, expiry.strftime('%Y-%m-%d %H:%M:%S.%f')))  # Insert private key and expiration time
    get_db().commit()  # Commit the transaction

# Function to generate and return a new RSA private key


def generate_and_save_rsa_key(expiry=None):
    if expiry is None:
        # Default expiration time
        expiry = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )  # Generate a new RSA private key
    # Save the private key to the database
    save_private_key_to_db(private_key, expiry)
    return private_key

# Function to convert an RSA private key to a JWK (JSON Web Key)


def rsa_to_jwks(private_key, kid, expiry):
    public_key = private_key.public_key()  # Get the public key
    pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode('utf-8')  # Serialize the public key to PEM format
    jwk = {
        "kid": kid,
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "n": public_key.public_numbers().n,
        "e": public_key.public_numbers().e,
        # Convert expiration time to string
        "exp": expiry.strftime('%Y-%m-%d %H:%M:%S.%f'),
    }  # Create a JSON Web Key (JWK)
    return jwk

# Function to retrieve active keys from the database based on expiration timestamp


def get_active_keys():
    current_time = datetime.datetime.utcnow()  # Get the current UTC time
    with app.app_context():  # Create an application context
        cursor = get_cursor()  # Get a cursor
        cursor.execute(
            'SELECT key, exp FROM keys WHERE exp > ?', (current_time.strftime('%Y-%m-%d %H:%M:%S.%f'),))  # Query active keys
        rows = cursor.fetchall()  # Fetch the results
        active_keys = []  # Initialize a list for active keys
        for row in rows:
            private_key = serialization.load_pem_private_key(
                row[0], password=None)  # Load the private key from the database
            active_keys.append({
                "kid": None,
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "n": private_key.private_numbers().public_numbers.n,
                "e": private_key.private_numbers().public_numbers.e,
                "exp": row[1],
            })  # Convert the private key to a JWK and add to active keys
        return active_keys  # Return the list of active keys


# Create the 'keys' table if it doesn't exist
create_keys_table()

# Retrieve a list of active keys from the database
keys = get_active_keys()

# ======================================================================================
# Attempt to delete the database file when closing the server but keep encoutering error:
# Error deleting the database file: [WinError 32] The process cannot access the file because it is being used by another process: 'totally_not_my_privateKeys.db'
# def cleanup_database():
#     with app.app_context():
#         if 'db' in g:
#             # Close the database connection
#             g.db.close()
#             del g.db  # Remove the database connection from the context
#         db_file = 'totally_not_my_privateKeys.db'
#         if os.path.exists(db_file):
#             try:
#                 # Attempt to remove the database file if it exists
#                 os.remove(db_file)
#                 print("Database file deleted successfully.")
#             except Exception as e:
#                 print(f"Error deleting the database file: {e}")


# Register the cleanup function to be called when the app is closing
# atexit.register(cleanup_database)
# ========================================================================================
# Endpoint to generate and store a key that expires in 1 second


@app.route('/generate-key/1-second', methods=['POST'])
def generate_and_store_key_1_second():
    expiry = datetime.datetime.utcnow(
    ) + datetime.timedelta(seconds=1)  # Set expiration time
    private_key = generate_and_save_rsa_key(
        expiry)  # Generate and save a new RSA key

    # Check if the key is not expired before appending it to the keys list
    if expiry > datetime.datetime.utcnow():
        keys.append(rsa_to_jwks(private_key, None, expiry))

    return jsonify({"message": "Key generated and stored successfully"})

# Endpoint to generate and store a key that expires in 1 minute


@app.route('/generate-key/1-minute', methods=['POST'])
def generate_and_store_key_1_minute():
    expiry = datetime.datetime.utcnow(
    ) + datetime.timedelta(minutes=1)  # Set expiration time
    private_key = generate_and_save_rsa_key(
        expiry)  # Generate and save a new RSA key

    # Check if the key is not expired before appending it to the keys list
    if expiry > datetime.datetime.utcnow():
        keys.append(rsa_to_jwks(private_key, None, expiry))

    return jsonify({"message": "Key generated and stored successfully"})

# Endpoint to get the active keys


@app.route('/.well-known/jwks.json', methods=['GET'])
def get_jwks():
    current_time = datetime.datetime.utcnow()  # Get the current UTC time
    valid_keys = [key for key in keys if datetime.datetime.strptime(
        key["exp"], '%Y-%m-%d %H:%M:%S.%f') > current_time]
    return jsonify({"keys": valid_keys})

# authentication end point


@app.route('/auth', methods=['POST'])
def authenticate():
    if request.authorization:
        username = request.authorization.username
        password = request.authorization.password
        expired = request.args.get('expired')
        if username == "userABC" and password == "password123":
            kid = "sample-key"
            expiry = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            if expired:
                expiry = datetime.datetime.utcnow() - datetime.timedelta(hours=1)  # Expired
            private_key = generate_and_save_rsa_key(expiry)
            jwk = rsa_to_jwks(private_key, kid, expiry)
            keys.append(jwk)
            payload = {
                "sub": username,
                "iat": datetime.datetime.utcnow(),
                # Convert to string
                "exp": expiry.strftime('%Y-%m-%d %H:%M:%S.%f'),
            }
            token = jwt.encode(payload, private_key, algorithm="RS256")
            header = {
                "kid": kid,
                "alg": "RS256",
                "typ": "JWT",
            }
            jwt_with_kid = jwt.encode(
                payload, private_key, algorithm="RS256", headers=header)
            return jsonify({"token": jwt_with_kid})
    return jsonify({"error": "Authentication failed"}), 401


# Run the Flask app on port 8080
if __name__ == '__main__':
    app.run(port=8080, threaded=False)
