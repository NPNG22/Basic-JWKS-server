import unittest
import base64
import json
import datetime
from server import app, keys


class TestServer(unittest.TestCase):
    def setUp(self):
        # Create a test client
        self.app = app.test_client()

    def test_successful_authentication(self):
        # Test successful authentication
        username = "Bob"
        password = "rbLpY40aOFyBg7nweNleJQ"
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
        username = "userXYZ"  # Replace with an invalid test username
        password = "invalid_password"  # Replace with an invalid password
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
        response = self.app.get('/.well-known/jwks.json')
        self.assertEqual(response.status_code, 200)
        jwks_data = json.loads(response.data.decode('utf-8'))
        self.assertIn('keys', jwks_data)
        self.assertIsInstance(jwks_data['keys'], list)

    def test_expired_authentication(self):
        # Test authentication with expired key and "expired" query parameter
        username = "userABC"  # Replace with a valid test username
        password = "password123"  # Replace with the corresponding password
        credentials = base64.b64encode(
            f"{username}:{password}".encode()).decode()
        response = self.app.post(
            '/auth?expired=true',
            headers={'Authorization': f'Basic {credentials}'}
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data.decode('utf-8'))
        self.assertIn('token', data)

    def test_jwks_expired_keys(self):
        # Test that the JWKS endpoint does not return expired keys
        current_time = datetime.datetime.utcnow()
        expired_keys = [key for key in keys if datetime.datetime.strptime(
            key["exp"], '%Y-%m-%d %H:%M:%S.%f') <= current_time]

        response = self.app.get('/.well-known/jwks.json')
        self.assertEqual(response.status_code, 200)
        jwks_data = json.loads(response.data.decode('utf-8'))
        self.assertIn('keys', jwks_data)
        self.assertIsInstance(jwks_data['keys'], list)

        for expired_key in expired_keys:
            self.assertNotIn(expired_key, jwks_data['keys'])

    def test_jwks_structure(self):
        # Test the structure of the JWKS returned
        response = self.app.get('/.well-known/jwks.json')
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
