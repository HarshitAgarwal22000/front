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

test_user_id = 1
test_username = 'testuser'
test_token = generate_jwt(test_user_id, test_username)

def test_manage_dns_zones(client):
   
    response = client.get('/zones')
    assert response.status_code == 401


    response = client.get('/zones', headers={'Authorization': f'{test_token}'})
    assert response.status_code == 200

 
    data = {}
    response = client.post('/zones', json=data, headers={'Authorization': f'{test_token}'})
    assert response.status_code == 400
def test_manage_dns_zone(client):
 
    response = client.patch('/zones/example.com')
    assert response.status_code == 401

    data = {
        'zoneName': 'example.com',
        'zoneDetails': 'name',
        'recorded': 'new-name'
    }
    response = client.patch('/zones/example.com', json=data, headers={'Authorization': f'{test_token}'})
    assert response.status_code == 200

    response = client.delete('/zones/nonexistent.com', headers={'Authorization': f'{test_token}'})
    assert response.status_code == 404
def test_manage(client):
  
    response = client.get('/zones/1')
    assert response.status_code == 401

    response = client.get('/zones/1', headers={'Authorization': f'{test_token}'})
    assert response.status_code == 200

    data = {
        'zoneidr': 'example.com',
        'zonenamr': 'example',
        'zonelastcheckr': 'invalid-check',
        'zonetyper': 'invalid-type'
    }
    response = client.post('/zones/1', json=data, headers={'Authorization': '{test_token}'})
    assert response.status_code == 400


def test_man(client):

    response = client.delete('/zones/1/A')
    assert response.status_code == 401

   
    response = client.delete('/zones/1/A', headers={'Authorization': '{test_token}'})
    assert response.status_code == 200

    response = client.get('/zones/1/A')
    assert response.status_code == 401

    response = client.get('/zones/1/A', headers={'Authorization': '{test_token}'})
    assert response.status_code == 200


def test_mans(client):
    response = client.get('/zones/A')
    assert response.status_code == 401
    response = client.get('/zones/A', headers={'Authorization': '{test_token}'})
    assert response.status_code == 200
def test_sign_in(client):

    data = {
        'username': 'testuser.com',
        'password': 'testpassword',
        'phonenumberr': '1234567890'
    }
    response = client.post('/signup', json=data)
    assert response.status_code == 200

    response = client.post('/signup', json=data, headers={'Authorization': 'Bearer invalid-token'})
    assert response.status_code == 401

    login_data = {
        'Login-User': 'testuser',
        'Login-Password': 'testpassword'
    }
    response = client.post('/login', json=login_data)
    assert response.status_code == 200

    login_data = {
        'Login-User': 'testuser',
        'Login-Password': 'wrongpassword'
    }
    response = client.post('/login', json=login_data)
    assert response.status_code == 401


if __name__ == '__main__':
    pytest.main()
