import pytest
from app import create_app
from extensions import db

@pytest.fixture
def client():
    app = create_app()
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'JWT_SECRET_KEY': 'test-key'
    })

    with app.test_client() as client:
        with app.app_context():
            db.create_all()
        yield client

@pytest.fixture
def token(client):
    client.post('/auth/register', json={
        "username": "tester",
        "email": "tester@test.com",
        "password": "123456"
    })
    res = client.post('/auth/login', json={
        "username": "tester",
        "password": "123456"
    })
    return res.get_json()['access_token']

def test_create_producto(client, token):
    res = client.post('/api/productos', json={
        "nombre": "Teclado",
        "precio": 100,
        "descripcion": "Mecánico",
        "categoria": "Periféricos",
        "stock": 5
    }, headers={'Authorization': f'Bearer {token}'})

    assert res.status_code == 201
    assert b'Producto creado exitosamente' in res.data

def test_get_productos(client, token):
    test_create_producto(client, token)
    res = client.get('/api/productos')
    data = res.get_json()
    assert res.status_code == 200
    assert 'productos' in data
    assert len(data['productos']) >= 1

def test_buscar_producto(client, token):
    client.post('/api/productos', json={
        "nombre": "Laptop Gamer",
        "precio": 1500,
        "descripcion": "Alta gama",
        "categoria": "Computadoras",
        "stock": 3
    }, headers={'Authorization': f'Bearer {token}'})

    res = client.get('/api/productos/buscar?q=laptop')
    assert res.status_code == 200
    assert res.get_json()['total'] >= 1

def test_update_producto_parcial(client, token):
    # Crear
    res = client.post('/api/productos', json={
        "nombre": "Mouse",
        "precio": 25,
        "stock": 10
    }, headers={'Authorization': f'Bearer {token}'})
    producto_id = res.get_json()['producto']['id']

    # Actualizar parcial
    update_res = client.patch(f'/api/productos/{producto_id}', json={
        "precio": 20,
        "stock": 15
    }, headers={'Authorization': f'Bearer {token}'})

    assert update_res.status_code == 200
    updated = update_res.get_json()['producto']
    assert updated['precio'] == 20
    assert updated['stock'] == 15

def test_delete_producto(client, token):
    res = client.post('/api/productos', json={
        "nombre": "Eliminar Producto",
        "precio": 10,
        "stock": 1
    }, headers={'Authorization': f'Bearer {token}'})
    producto_id = res.get_json()['producto']['id']

    delete_res = client.delete(f'/api/productos/{producto_id}', headers={
        'Authorization': f'Bearer {token}'
    })

    assert delete_res.status_code == 200
    assert b'Producto eliminado exitosamente' in delete_res.data
