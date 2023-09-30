from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding
import datetime
import jwt

app = Flask(__name__)

# Store RSA keys with kid (Key ID) and expiry timestamp
keys = []

# Generate a new RSA key pair


def generate_rsa_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # Commonly used public exponent value
        key_size=2048,  # Key size in bits (2048 bits for security)
    )
    # Return the generated private key
    return private_key

# Convert RSA key to JWKS (JSON Web Key Set) format


def rsa_to_jwks(private_key, kid, expiry):
    # Get the public key from the provided private key
    public_key = private_key.public_key()
    # Convert the public key to PEM format and decode it to a string
    pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode('utf-8')
    # Create a JSON Web Key (JWK) with the following fields
    jwk = {
        "kid": kid,  # Key ID
        "kty": "RSA",  # Key Type
        "alg": "RS256",  # Algorithm (RS256 for RSA-SHA256)
        "use": "sig",  # Use (for signature)
        # Modulus (n) - Large integer value)
        "n": public_key.public_numbers().n,
        "e": public_key.public_numbers().e,  # Exponent (e) - Small integer value
        "exp": expiry,  # Expiration Time (timestamp)
    }
    return jwk

# Retrieve a list of active keys based on expiration timestamp


@app.route('/.well-known/jwks.json', methods=['GET'])
def get_jwks():
    current_time = datetime.datetime.utcnow()
    # Filter and return only active keys (keys that have not expired)
    active_keys = [key for key in keys if key['exp'] > current_time]
    jwks = {
        "keys": active_keys,
    }
    return jsonify(jwks)

# Authentication for blackbox


@app.route('/auth', methods=['POST'])
def authenticate():
    if request.authorization:
        username = request.authorization.username
        password = request.authorization.password
        # Check if "expired" query parameter is present
        expired = request.args.get('expired')
        # Simulate successful authentication
        if username == "userABC" and password == "password123":
            # Generate and return a JWT (JSON Web Token)
            kid = "sample-key"
            expiry = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            # For testing purposes, use an expired key and expiry timestamp if "expired" is present
            if expired:
                # Use an expired key and expiry timestamp for testing
                expiry = datetime.datetime.utcnow() - datetime.timedelta(hours=1)  # Expired
            private_key = generate_rsa_key()
            jwk = rsa_to_jwks(private_key, kid, expiry)
            keys.append(jwk)  # Store the new key temporarily
            # Define the payload for the JWT
            payload = {
                "sub": username,  # Subject
                "iat": datetime.datetime.utcnow(),  # Issued At
                "exp": expiry,  # Expiration Time
            }
            # Encode the payload and sign the JWT using the private key
            token = jwt.encode(payload, private_key, algorithm="RS256")
            # Include the kid in the JWT header
            header = {
                "kid": kid,
                "alg": "RS256",
                "typ": "JWT"
            }
            # Encode the JWT with header and payload, and sign it with the private key
            jwt_with_kid = jwt.encode(
                payload, private_key, algorithm="RS256", headers=header)
            # Return the JWT with kid in a JSON response
            return jsonify({"token": jwt_with_kid})
    # If authentication fails, return an error response with a 401 status code
    return jsonify({"error": "Authentication failed"}), 401


# Run the Flask app on port 8080
if __name__ == '__main__':
    app.run(port=8080)
