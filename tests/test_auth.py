import pytest
from app import create_app
from extensions import db
from models.usuario import Usuario

@pytest.fixture
def client():
    app = create_app()
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'JWT_SECRET_KEY': 'test-secret-key'
    })

    with app.test_client() as client:
        with app.app_context():
            db.create_all()
        yield client

def test_register_user(client):
    res = client.post('/auth/register', json={
        "username": "testuser2",
        "email": "test2@example.com",
        "password": "123456",
        "nombre": "Nombre",
        "apellido": "Apellido"
    })
    print(">>", res.get_json())
    assert res.status_code == 201
    assert b'Usuario creado exitosamente' in res.data

def test_login_user(client):
    # Primero registramos
    client.post('/auth/register', json={
        "username": "testuser",
        "email": "test@example.com",
        "password": "123456"
    })

    res = client.post('/auth/login', json={
        "username": "testuser",
        "password": "123456"
    })

    assert res.status_code == 200
    json_data = res.get_json()
    assert 'access_token' in json_data

def test_get_current_user_requires_auth(client):
    res = client.get('/auth/me')
    assert res.status_code == 401  # Unauthorized

def test_get_current_user_with_token(client):
    # Registrar y loguear para obtener token
    client.post('/auth/register', json={
        "username": "testuser",
        "email": "test@example.com",
        "password": "123456"
    })
    login_res = client.post('/auth/login', json={
        "username": "testuser",
        "password": "123456"
    })
    token = login_res.get_json()['access_token']

    res = client.get('/auth/me', headers={
        'Authorization': f'Bearer {token}'
    })

    assert res.status_code == 200
    assert 'username' in res.get_json()
