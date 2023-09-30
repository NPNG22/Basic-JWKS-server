import unittest
import base64
import json
import datetime
from server import app


class TestServer(unittest.TestCase):
    def setUp(self):
        # Create a test client
        self.app = app.test_client()

    def test_successful_authentication(self):
        # Test successful authentication
        username = "userABC"
        password = "password123"
        credentials = base64.b64encode(
            f"{username}:{password}".encode()).decode()
        response = self.app.post(
            '/auth',
            headers={'Authorization': f'Basic {credentials}'}
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data.decode('utf-8'))
        self.assertIn('token', data)

    def test_failed_authentication(self):
        # Test authentication with invalid credentials
        username = "userXYZ"
        password = "invalid_password"
        credentials = base64.b64encode(
            f"{username}:{password}".encode()).decode()
        response = self.app.post(
            '/auth',
            headers={'Authorization': f'Basic {credentials}'}
        )
        self.assertEqual(response.status_code, 401)
        data = json.loads(response.data.decode('utf-8'))
        self.assertIn('error', data)
        self.assertEqual(data['error'], "Authentication failed")

    def test_jwks_endpoint(self):
        # Test the JWKS endpoint to ensure it returns the expected structure
        response = self.app.get('/.well-known/jwks.json')  # Update the URL
        self.assertEqual(response.status_code, 200)
        jwks_data = json.loads(response.data.decode('utf-8'))
        self.assertIn('keys', jwks_data)
        self.assertIsInstance(jwks_data['keys'], list)

    def test_expired_authentication(self):
        # Test authentication with expired key and "expired" query parameter
        username = "userABC"
        password = "password123"
        credentials = base64.b64encode(
            f"{username}:{password}".encode()).decode()
        response = self.app.post(
            '/auth?expired=true',  # Add "expired" query parameter
            headers={'Authorization': f'Basic {credentials}'}
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data.decode('utf-8'))
        self.assertIn('token', data)

    def test_jwks_expired_keys(self):
        # Define a list of keys for testing (mock keys)
        keys = []
        # Test the JWKS endpoint to ensure it does not return expired keys
        # Add an expired key to the list of keys
        expired_key = {
            "kid": "expired-key",
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "n": "expired-key-n",
            "e": "expired-key-e",
            "exp": (datetime.datetime.utcnow() -
                    datetime.timedelta(minutes=60)).timestamp()
        }
        keys.append(expired_key)
        response = self.app.get('/.well-known/jwks.json')  # Update the URL
        self.assertEqual(response.status_code, 200)
        jwks_data = json.loads(response.data.decode('utf-8'))
        self.assertIn('keys', jwks_data)
        self.assertIsInstance(jwks_data['keys'], list)
        # Ensure that the expired key is not present in the JWKS
        self.assertNotIn(expired_key, jwks_data['keys'])

    def test_jwks_structure(self):
        # Test the structure of the JWKS returned
        response = self.app.get('/.well-known/jwks.json')  # Update the URL
        self.assertEqual(response.status_code, 200)
        jwks_data = json.loads(response.data.decode('utf-8'))
        self.assertIn('keys', jwks_data)
        self.assertIsInstance(jwks_data['keys'], list)
        # Ensure each key in the JWKS has the expected attributes
        for key in jwks_data['keys']:
            self.assertIn('kid', key)
            self.assertIn('kty', key)
            self.assertIn('alg', key)
            self.assertIn('use', key)
            self.assertIn('n', key)
            self.assertIn('e', key)
            self.assertIn('exp', key)


if __name__ == '__main__':
    unittest.main()
