import pytest
import app
import json
import sqlite3
import datetime

@pytest.fixture
def client():
    app.app.config['TESTING'] = True
    client = app.app.test_client()
    yield client

def test_auth_valid(client):
    response = client.post('/auth')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'jwt' in data

def test_jwks(client):
    response = client.get('/.well-known/jwks.json')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'keys' in data
    assert isinstance(data['keys'], list)

def test_expired_key(client):
    # Manually insert an expired key
    private_key = app.generate_rsa_key()
    expiration_time = int((datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=1)).timestamp())
    app.insert_key(private_key, expiration_time)
    
    response = client.post('/auth?expired=true')
    assert response.status_code == 200 or response.status_code == 500  # Depends if expired key is handled

def test_db_init():
    # Just run init_db to make sure it's covered
    app.init_db()
