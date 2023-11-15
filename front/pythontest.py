import pytest
import json
from backend import NEWPD
from NEWPD import app
import jwt
import hvac
@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


SECRET_KEY="DUBAI"
def generate_jwt(uid,username):
 
        payload={"uid":uid,"username":username}
        token=jwt.encode(payload,SECRET_KEY,algorithm='HS256')
        print(token)
        return token
# Define a test user and token for authentication testing
test_user_id = 1
test_username = 'testuser'
test_token = generate_jwt(test_user_id, test_username)

def test_manage_dns_zones(client):
    # Test GET request without a token (should fail)
    response = client.get('/zones')
    assert response.status_code == 401

    # Test GET request with a valid token (should succeed)
    response = client.get('/zones', headers={'Authorization': f'{test_token}'})
    assert response.status_code == 200

    # Test POST request with missing fields (should fail)
    data = {}
    response = client.post('/zones', json=data, headers={'Authorization': f'{test_token}'})
    assert response.status_code == 400

    # Add more tests for POST request with and without a token, including edge cases

def test_manage_dns_zone(client):
    # Test PATCH request without a token (should fail)
    response = client.patch('/zones/example.com')
    assert response.status_code == 401

    # Test PATCH request with a valid token (should succeed)
    data = {
        'zoneName': 'example.com',
        'zoneDetails': 'name',
        'recorded': 'new-name'
    }
    response = client.patch('/zones/example.com', json=data, headers={'Authorization': f'{test_token}'})
    assert response.status_code == 200

    # Test DELETE request for a non-existent zone (should fail)
    response = client.delete('/zones/nonexistent.com', headers={'Authorization': f'{test_token}'})
    assert response.status_code == 404

    # Add more tests for DELETE request with and without a token

def test_manage(client):
    # Test GET request without a token (should fail)
    response = client.get('/zones/1')
    assert response.status_code == 401

    # Test GET request with a valid token (should succeed)
    response = client.get('/zones/1', headers={'Authorization': f'{test_token}'})
    assert response.status_code == 200

    # Test POST request with invalid data (should fail)
    data = {
        'zoneidr': 'example.com',
        'zonenamr': 'example',
        'zonelastcheckr': 'invalid-check',
        'zonetyper': 'invalid-type'
    }
    response = client.post('/zones/1', json=data, headers={'Authorization': '{test_token}'})
    assert response.status_code == 400

    # Add more tests for POST, DELETE, and PATCH requests with and without a token

def test_man(client):
    # Test DELETE request without a token (should fail)
    response = client.delete('/zones/1/A')
    assert response.status_code == 401

    # Test DELETE request with a valid token (should succeed)
    response = client.delete('/zones/1/A', headers={'Authorization': '{test_token}'})
    assert response.status_code == 200

    # Test GET request without a token (should fail)
    response = client.get('/zones/1/A')
    assert response.status_code == 401

    # Test GET request with a valid token (should succeed)
    response = client.get('/zones/1/A', headers={'Authorization': '{test_token}'})
    assert response.status_code == 200

    # Add more tests for other HTTP methods with and without a token

def test_mans(client):
    # Test GET request without a token (should fail)
    response = client.get('/zones/A')
    assert response.status_code == 401

    # Test GET request with a valid token (should succeed)
    response = client.get('/zones/A', headers={'Authorization': '{test_token}'})
    assert response.status_code == 200

    # Add more tests for other HTTP methods with and without a token

def test_sign_in(client):
    # Test user sign-up without a token (should succeed)
    data = {
        'username': 'testuser.com',
        'password': 'testpassword',
        'phonenumberr': '1234567890'
    }
    response = client.post('/signup', json=data)
    assert response.status_code == 200

    # Test user sign-up with an invalid token (should fail)
    response = client.post('/signup', json=data, headers={'Authorization': 'Bearer invalid-token'})
    assert response.status_code == 401

    # Test user login with correct credentials (should succeed)
    login_data = {
        'Login-User': 'testuser',
        'Login-Password': 'testpassword'
    }
    response = client.post('/login', json=login_data)
    assert response.status_code == 200

    # Test user login with incorrect credentials (should fail)
    login_data = {
        'Login-User': 'testuser',
        'Login-Password': 'wrongpassword'
    }
    response = client.post('/login', json=login_data)
    assert response.status_code == 401

# Add more test cases covering additional routes, edge cases, and error handling

if __name__ == '__main__':
    pytest.main()
