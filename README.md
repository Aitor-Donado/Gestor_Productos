# API RESTful con SQLAlchemy y Auth

### **1. Base de Datos SQLAlchemy**

- ✅ **Archivo .env** con `DATABASE_URL` y configuración
- ✅ **SQLAlchemy** integrado en `app.py` con migraciones
    - **Migraciones** con Flask-Migrate para evolución de esquema
- ✅ **Modelos completos** para Producto y Usuario
    - **Modelo Producto** completo con timestamps, validaciones y métodos helper
    - **Modelo Usuario** preparado para autenticación con hash de contraseñas

### 📊 **Modelo Producto:**

- `id`, `nombre`, `precio` (campos básicos)
- `descripcion`, `categoria`, `stock` (campos adicionales)
- `activo` (soft delete), `fecha_creacion`, `fecha_actualizacion`
- Métodos `to_dict()` y `from_dict()` para serialización

```python
# Campos completos
id, nombre, precio, descripcion, categoria, stock, activo
fecha_creacion, fecha_actualizacion

# Métodos útiles
to_dict()        # Para JSON responses
from_dict()      # Para crear desde JSON
```

### 🔐 **Modelo Usuario:**

- `username`, `email`, `password_hash`
- `nombre`, `apellido`, `activo`
- Métodos `set_password()` y `check_password()` con Werkzeug
- Timestamps de creación y último acceso

```python
# Campos de usuario
username, email, password_hash, nombre, apellido
activo, fecha_creacion, ultimo_acceso

# Métodos de seguridad
set_password()   # Hashea contraseñas
check_password() # Verifica contraseñas
```

### **2. API Mejorada**

- 🔄 **Paginación** automática (`?page=1&per_page=10`)
- 🔍 **Filtros** por categoría y estado
- 💪 **Manejo de errores** SQLAlchemy con rollback
- ✅ **Validaciones** robustas para todos los campos

### **3. Configuración Profesional**

- 📄 **`.env`** para variables sensibles
- 🚫 **`.gitignore`** para proteger datos
- 📦 **`requirements.txt`** actualizado
- 🗂️ **Estructura modular** escalable

## 🧱 Creación del proyecto

```bash
# 1. Crear proyecto
mkdir proyecto_flask && cd proyecto_flask
# 2. Instalar dependencias
pip install -r requirements.txt
```

### Los requerimientos en `requirements.txt` son:

```
alembic==1.16.1
bcrypt==4.3.0
blinker==1.9.0
click==8.2.1
Flask==2.3.3
Flask-Bcrypt==1.0.1
Flask-JWT-Extended==4.5.3
Flask-Migrate==3.1.0
Flask-SQLAlchemy==3.0.5
greenlet==3.2.3
itsdangerous==2.2.0
Jinja2==3.1.6
Mako==1.3.10
MarkupSafe==3.0.2
PyJWT==2.10.1
python-dotenv==1.0.0
SQLAlchemy==2.0.41
typing_extensions==4.14.0
Werkzeug==2.3.7
```

## 🚀 **Para Ejecutar:**

```bash
# 3. Configurar .env
# DATABASE_URL=sqlite:///productos.db
# SECRET_KEY=tu-clave-secreta

# 4. Inicializar BD
python app.py

# 5. Probar API
curl http://localhost:5000/api/productos
```

## Características Implementadas

### 🚀 **API Mejorada:**

- **Paginación** automática en listado de productos
- **Filtros** por categoría y estado activo
- **Manejo de errores** robusto con try/catch SQLAlchemy
- **Validaciones** mejoradas para todos los campos
- **Transacciones** con rollback automático en errores

### 📁 **Estructura de Archivos Completa:**

```
proyecto_flask/
├── app.py                 # Aplicación principal
├── extensions.py          # Extensiones SQLAlchemy, Migrate, etc.
├── config.py             # Configuraciones
├── requirements.txt      # Dependencias
├── .env                  # Variables de entorno
├── .gitignore           # Archivos a ignorar
├── blueprints/
│   ├── __init__.py
│   └── productos.py      # Blueprint de productos
├── models/
│   ├── __init__.py
│   ├── producto.py       # Modelo de producto
│   └── usuario.py        # Modelo de usuario
├── utils/
│   ├── __init__.py
│   └── validators.py     # Validadores
├── migrations/           # Migraciones de base de datos
└── tests/
    ├── __init__.py
    └── test_productos.py  # Tests unitarios

```

## Próximos Pasos

1. **🧪** Tests unitarios y de integración

## Inicialización del Proyecto

### 1. Crear el proyecto:

```bash
mkdir proyecto_flask
cd proyecto_flask
python -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate
```

### 2. Instalar dependencias:

```bash
pip install -r requirements.txt
```

### 3. Configurar variables de entorno:

```bash
# Copiar .env y ajustar valores
cp .env.example .env
# Editar DATABASE_URL, SECRET_KEY, etc.
```

### 4. Inicializar base de datos:

```bash
# Opción 1: Con migraciones
flask db init
flask db migrate -m "Initial migration"
flask db upgrade

# Opción 2: Creación directa
python app.py
```

### 5. Ejecutar aplicación:

```bash
python app.py
```

## Estado Actual

- ✅ **Estructura de proyecto** organizada con blueprints
- ✅ **Base de datos SQLAlchemy** configurada con .env
- ✅ **Modelo Producto** completo con campos avanzados
- ✅ **Modelo Usuario** preparado para autenticación
- ✅ **API CRUD** completa con validaciones y paginación
- ✅ **Manejo de errores** robusto
- 🔄 **Listo para autenticación** JWT# Estructura del Proyecto Flask API

```
proyecto_flask/
├── app.py                # Aplicación principal
├── config.py             # Configuraciones
├── requirements.txt      # Dependencias
├── .env                  # Variables de entorno
├── .gitignore            # Archivos a ignorar
├── blueprints/
│   ├── __init__.py
│   ├── auth.py           # Sistema de autenticación
│   └── productos.py      # Blueprint de productos
├── models/
│   ├── __init__.py
│   ├── producto.py       # Modelo de producto
│   └── usuario.py        # Modelo de usuario
├── utils/
│   ├── __init__.py
│   └── validators.py     # Validadores
├── migrations/           # Migraciones de base de datos
└── tests/
    ├── __init__.py
    └── test_productos.py  # Tests unitarios

```

## Archivos del Proyecto

### 0. extensions.py

```python
# Base de datos
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
# Encriptación y JWT
from flask_jwt_extended import JWTManager
from flask_bcrypt import Bcrypt

# Inicializar extensiones
db = SQLAlchemy()
migrate = Migrate()
bcrypt = Bcrypt()
jwt = JWTManager()
```

### 1. app.py (Aplicación Principal)

```python
from flask import Flask
from extensions import db, migrate
from extensions import bcrypt, jwt
from blueprints.productos import productos_bp
from blueprints.auth import auth_bp

def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')
    
    # Inicializar extensiones
    # Para la base de datos
    db.init_app(app)
    migrate.init_app(app, db)
    # Para logueo de usuarios
    bcrypt.init_app(app)
    jwt.init_app(app)
    
    # Importar modelos para que SQLAlchemy los reconozca
    from models import producto, usuario
    
    # Registrar blueprints
    from blueprints.productos import productos_bp
    from blueprints.auth import auth_bp
    app.register_blueprint(productos_bp, url_prefix='/api')
    app.register_blueprint(auth_bp, url_prefix='/auth')
    return app

# Para desarrollo directo
if __name__ == '__main__':
    app = create_app()
    
    # Crear tablas si no existen (solo para desarrollo)
    with app.app_context():
        db.create_all()
    
    app.run(debug=True)
```

### 2. config.py (Configuraciones)

```python
import os
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///default.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    DEBUG = os.getenv('DEBUG', 'True').lower() == 'true'
    
    # Configuración de JWT para autenticación de usuarios
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'jwt-secret-key-cambiar-en-produccion')
    JWT_ACCESS_TOKEN_EXPIRES = int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES', '3600'))
    # Habilitar lista negra (blacklist)
    JWT_BLACKLIST_ENABLED = True
    JWT_BLACKLIST_TOKEN_CHECKS = ['access']  
    # También puedes incluir 'refresh' si lo usas
```

### 3. .env (Variables de Entorno)

```
# Base de datos
DATABASE_URL=sqlite:///productos.db

# Configuración de la aplicación
SECRET_KEY=tu-clave-secreta-aqui-cambiar-en-produccion
DEBUG=true

# JWT (para autenticación futura)
JWT_SECRET_KEY=jwt-secret-key-cambiar-en-produccion
JWT_ACCESS_TOKEN_EXPIRES=3600

```

### 4. .gitignore

```
# Variables de entorno
.env

# Base de datos
*.db
*.sqlite

# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
env/
venv/
ENV/
env.bak/
venv.bak/

# Flask
instance/
.webassets-cache

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

```

### 5. models/producto.py (Modelo de Producto)

```python
from datetime import datetime
from app import db

class Producto(db.Model):
    __tablename__ = 'productos'

    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    precio = db.Column(db.Float, nullable=False)
    descripcion = db.Column(db.Text, nullable=True)
    categoria = db.Column(db.String(50), nullable=True)
    stock = db.Column(db.Integer, default=0)
    activo = db.Column(db.Boolean, default=True)
    fecha_creacion = db.Column(db.DateTime, default=datetime.utcnow)
    fecha_actualizacion = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<Producto {self.nombre}>'

    def to_dict(self):
        """Convierte el objeto a diccionario para JSON"""
        return {
            'id': self.id,
            'nombre': self.nombre,
            'precio': self.precio,
            'descripcion': self.descripcion,
            'categoria': self.categoria,
            'stock': self.stock,
            'activo': self.activo,
            'fecha_creacion': self.fecha_creacion.isoformat() if self.fecha_creacion else None,
            'fecha_actualizacion': self.fecha_actualizacion.isoformat() if self.fecha_actualizacion else None
        }

    @staticmethod
    def from_dict(data):
        """Crea un producto desde un diccionario"""
        return Producto(
            nombre=data.get('nombre'),
            precio=data.get('precio'),
            descripcion=data.get('descripcion'),
            categoria=data.get('categoria'),
            stock=data.get('stock', 0),
            activo=data.get('activo', True)
        )

```

### 6. utils/validators.py

```python
def validate_email(email):
    """Valida formato de email"""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    """Valida que la contraseña tenga al menos 6 caracteres"""
    return len(password) >= 6
```

### 7. models/usuario.py (Modelo de Usuario)

```python
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from app import db

class Usuario(db.Model):
    __tablename__ = 'usuarios'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    nombre = db.Column(db.String(100), nullable=True)
    apellido = db.Column(db.String(100), nullable=True)
    activo = db.Column(db.Boolean, default=True)
    fecha_creacion = db.Column(db.DateTime, default=datetime.utcnow)
    ultimo_acceso = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f'<Usuario {self.username}>'

    def set_password(self, password):
        """Hashea y guarda la contraseña"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Verifica la contraseña"""
        return check_password_hash(self.password_hash, password)

    def to_dict(self, include_sensitive=False):
        """Convierte el objeto a diccionario para JSON"""
        data = {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'nombre': self.nombre,
            'apellido': self.apellido,
            'activo': self.activo,
            'fecha_creacion': self.fecha_creacion.isoformat() if self.fecha_creacion else None,
            'ultimo_acceso': self.ultimo_acceso.isoformat() if self.ultimo_acceso else None
        }

        if include_sensitive:
            data['password_hash'] = self.password_hash

        return data

    @staticmethod
    def from_dict(data):
        """Crea un usuario desde un diccionario"""
        usuario = Usuario(
            username=data.get('username'),
            email=data.get('email'),
            nombre=data.get('nombre'),
            apellido=data.get('apellido'),
            activo=data.get('activo', True)
        )
        if 'password' in data:
            usuario.set_password(data['password'])
        return usuario
		# método para verificar si el usuario está activo
		def is_active(self):
		    return self.activo
```

### 8. models/**init**.py

```python
from .producto import Producto
from .usuario import Usuario

__all__ = ['Producto', 'Usuario']
```

### 9. blueprints/productos.py (Blueprint de Productos)

```python
from flask import Blueprint, jsonify, request
from sqlalchemy.exc import SQLAlchemyError
from app import db
from models.producto import Producto

productos_bp = Blueprint('productos', __name__)

def validate_producto_data(data, required_fields=None):
    """Valida los datos del producto"""
    if not data:
        return False, "No se proporcionaron datos"

    # Campos requeridos por defecto
    if required_fields is None:
        required_fields = ['nombre', 'precio']

    # Verificar campos requeridos
    for field in required_fields:
        if field not in data or not str(data[field]).strip():
            return False, f"El campo '{field}' es requerido"

    # Validar precio si está presente
    if 'precio' in data:
        try:
            precio = float(data['precio'])
            if precio < 0:
                return False, "El precio no puede ser negativo"
        except (ValueError, TypeError):
            return False, "El precio debe ser un número válido"

    # Validar stock si está presente
    if 'stock' in data:
        try:
            stock = int(data['stock'])
            if stock < 0:
                return False, "El stock no puede ser negativo"
        except (ValueError, TypeError):
            return False, "El stock debe ser un número entero válido"

    return True, ""

# GET - Obtener todos los productos
@productos_bp.route('/productos', methods=['GET'])
def obtener_productos():
    try:
        # Parámetros de consulta opcionales
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        activo = request.args.get('activo', type=bool)
        categoria = request.args.get('categoria')

        # Construir query
        query = Producto.query

        if activo is not None:
            query = query.filter(Producto.activo == activo)

        if categoria:
            query = query.filter(Producto.categoria.ilike(f'%{categoria}%'))

        # Paginación
        productos_paginados = query.paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )

        return jsonify({
            'productos': [p.to_dict() for p in productos_paginados.items],
            'total': productos_paginados.total,
            'pagina': productos_paginados.page,
            'total_paginas': productos_paginados.pages,
            'por_pagina': productos_paginados.per_page
        })

    except SQLAlchemyError as e:
        return jsonify({'error': 'Error al obtener productos'}), 500

# GET - Obtener un producto específico
@productos_bp.route('/productos/<int:id>', methods=['GET'])
def obtener_producto(id):
    try:
        producto = Producto.query.get(id)
        if not producto:
            return jsonify({'error': 'Producto no encontrado'}), 404

        return jsonify(producto.to_dict())

    except SQLAlchemyError as e:
        return jsonify({'error': 'Error al obtener el producto'}), 500

# POST - Crear nuevo producto
@productos_bp.route('/productos', methods=['POST'])
def crear_producto():
    try:
        data = request.get_json()

        # Validar datos
        is_valid, error_message = validate_producto_data(data)
        if not is_valid:
            return jsonify({'error': error_message}), 400

        # Crear nuevo producto
        producto = Producto.from_dict(data)

        db.session.add(producto)
        db.session.commit()

        return jsonify({
            'mensaje': 'Producto creado exitosamente',
            'producto': producto.to_dict()
        }), 201

    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({'error': 'Error al crear el producto'}), 500

# PUT - Actualizar producto completo
@productos_bp.route('/productos/<int:id>', methods=['PUT'])
def actualizar_producto_completo(id):
    try:
        producto = Producto.query.get(id)
        if not producto:
            return jsonify({'error': 'Producto no encontrado'}), 404

        data = request.get_json()

        # Validar datos
        is_valid, error_message = validate_producto_data(data)
        if not is_valid:
            return jsonify({'error': error_message}), 400

        # Actualizar todos los campos
        producto.nombre = data['nombre'].strip()
        producto.precio = float(data['precio'])
        producto.descripcion = data.get('descripcion', '').strip()
        producto.categoria = data.get('categoria', '').strip()
        producto.stock = int(data.get('stock', 0))
        producto.activo = data.get('activo', True)

        db.session.commit()

        return jsonify({
            'mensaje': 'Producto actualizado exitosamente',
            'producto': producto.to_dict()
        })

    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({'error': 'Error al actualizar el producto'}), 500

# PATCH - Actualizar producto parcial
@productos_bp.route('/productos/<int:id>', methods=['PATCH'])
def actualizar_producto_parcial(id):
    try:
        producto = Producto.query.get(id)
        if not producto:
            return jsonify({'error': 'Producto no encontrado'}), 404

        data = request.get_json()
        if not data:
            return jsonify({'error': 'No se proporcionaron datos para actualizar'}), 400

        # Validar solo los campos que se van a actualizar
        campos_a_actualizar = [k for k in data.keys() if k in ['nombre', 'precio', 'stock']]
        if campos_a_actualizar:
            is_valid, error_message = validate_producto_data(data, required_fields=[])
            if not is_valid:
                return jsonify({'error': error_message}), 400

        # Actualizar solo los campos proporcionados
        if 'nombre' in data:
            producto.nombre = data['nombre'].strip()
        if 'precio' in data:
            producto.precio = float(data['precio'])
        if 'descripcion' in data:
            producto.descripcion = data['descripcion'].strip()
        if 'categoria' in data:
            producto.categoria = data['categoria'].strip()
        if 'stock' in data:
            producto.stock = int(data['stock'])
        if 'activo' in data:
            producto.activo = bool(data['activo'])

        db.session.commit()

        return jsonify({
            'mensaje': 'Producto actualizado exitosamente',
            'producto': producto.to_dict()
        })

    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({'error': 'Error al actualizar el producto'}), 500

# DELETE - Eliminar producto
@productos_bp.route('/productos/<int:id>', methods=['DELETE'])
def eliminar_producto(id):
    try:
        producto = Producto.query.get(id)
        if not producto:
            return jsonify({'error': 'Producto no encontrado'}), 404

        producto_eliminado = producto.to_dict()

        db.session.delete(producto)
        db.session.commit()

        return jsonify({
            'mensaje': 'Producto eliminado exitosamente',
            'producto_eliminado': producto_eliminado
        })

    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({'error': 'Error al eliminar el producto'}), 500

# GET - Buscar productos por nombre
@productos_bp.route('/productos/buscar', methods=['GET'])
def buscar_productos():
    try:
        query = request.args.get('q', '').strip()
        if not query:
            return jsonify({'error': 'Parámetro de búsqueda "q" requerido'}), 400

        productos = Producto.query.filter(
            Producto.nombre.ilike(f'%{query}%')
        ).all()

        return jsonify({
            'resultados': [p.to_dict() for p in productos],
            'total': len(productos),
            'busqueda': query
        })

    except SQLAlchemyError as e:
        return jsonify({'error': 'Error al buscar productos'}), 500

```

### 10. Blueprint de Autenticación (blueprints/auth.py)

```python
from flask import Blueprint, jsonify, request
from flask_jwt_extended import (
    create_access_token, jwt_required, get_jwt_identity,
    get_jwt  # ✅ Cambio aquí
)
from extensions import jwt
from models.usuario import Usuario
from app import db
from datetime import datetime, timezone
from utils.validators import validate_email, validate_password

auth_bp = Blueprint('auth', __name__)

# Lista negra de tokens revocados (en producción usar Redis)
BLACKLIST = set()

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    # Validaciones
    if not data.get('username') or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Username, email y contraseña son requeridos'}), 400

    if not validate_email(data['email']):
        return jsonify({'error': 'Email inválido'}), 400

    if not validate_password(data['password']):
        return jsonify({'error': 'Contraseña debe tener al menos 6 caracteres'}), 400

    if Usuario.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username ya existe'}), 400

    if Usuario.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email ya registrado'}), 400

    # Crear nuevo usuario
    usuario = Usuario.from_dict(data)
    usuario.set_password(data['password'])

    db.session.add(usuario)
    db.session.commit()

    return jsonify({
        'mensaje': 'Usuario creado exitosamente',
        'usuario': usuario.to_dict()
    }), 201

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data.get('username') and not data.get('email'):
        return jsonify({'error': 'Username o email requerido'}), 400

    if not data.get('password'):
        return jsonify({'error': 'Contraseña requerida'}), 400

    # Buscar usuario por username o email
    usuario = None
    if data.get('username'):
        usuario = Usuario.query.filter_by(username=data['username']).first()
    if not usuario and data.get('email'):
        usuario = Usuario.query.filter_by(email=data['email']).first()

    if not usuario or not usuario.check_password(data['password']):
        return jsonify({'error': 'Credenciales inválidas'}), 401

    # Actualizar último acceso
    usuario.ultimo_acceso = datetime.now(tz=timezone.utc)
    db.session.commit()

    # Crear token JWT
    access_token = create_access_token(identity=str(usuario.id))

    return jsonify({
        'access_token': access_token,
        'usuario': usuario.to_dict()
    })

@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()['jti'] 
    BLACKLIST.add(jti)
    return jsonify({'mensaje': 'Sesión cerrada exitosamente'})

# Middleware de protección
@jwt.revoked_token_loader
def check_if_token_in_blacklist(jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    return jsonify({'msg': 'Token has been revoked'}), 401

# Endpoint protegido de ejemplo
@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def get_current_user():
    current_user_id = get_jwt_identity()
    usuario = Usuario.query.get(current_user_id)
    if not usuario:
        return jsonify({'error': 'Usuario no encontrado'}), 404
    return jsonify(usuario.to_dict())

```

### 11. Comandos de Inicialización

```bash
# Instalar dependencias
pip install -r requirements.txt

# Crear migraciones iniciales
flask db init
flask db migrate -m "Initial migration"
flask db upgrade

# O usar Python directamente para crear las tablas
python app.py
```

## Ejemplos de Uso con Base de Datos desde la terminal

### Crear Producto (POST)

```bash
curl -X POST http://localhost:5000/api/productos \
  -H "Content-Type: application/json" \
  -d '{
    "nombre": "Teclado Mecánico",
    "precio": 75.5,
    "descripcion": "Teclado gaming con switches azules",
    "categoria": "Periféricos",
    "stock": 10
  }'
```

### Actualizar Producto Completo (PUT)

```bash
curl -X PUT http://localhost:5000/api/productos/1 \
  -H "Content-Type: application/json" \
  -d '{
    "nombre": "Laptop Gaming",
    "precio": 1500,
    "descripcion": "Laptop para gaming de alta gama",
    "categoria": "Computadoras",
    "stock": 5
  }'
```

### Actualizar Producto Parcial (PATCH)

```bash
curl -X PATCH http://localhost:5000/api/productos/1 \
  -H "Content-Type: application/json" \
  -d '{"precio": 1300, "stock": 3}'
```

### Eliminar Producto (DELETE)

```bash
curl -X DELETE http://localhost:5000/api/productos/1

```

### Obtener Productos con Paginación

```bash
curl "http://localhost:5000/api/productos?page=1&per_page=5&categoria=gaming"
```

### Buscar Productos

```bash
curl "http://localhost:5000/api/productos/buscar?q=laptop"
```

## Ejemplos de Uso para usuarios

### Registro

```bash
curl -X POST http://localhost:5000/auth/register \
  -H 'Content-Type: application/json' \
  -d '{
    "username": "admin",
    "email": "admin@example.com",
    "password": "123456",
    "nombre": "Admin",
    "apellido": "Principal"
  }'

```

### Login

```bash
curl -X POST http://localhost:5000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{
    "username": "admin",
    "password": "123456"
  }'

```

### Acceso a Ruta Protegida

```bash
curl -X GET http://localhost:5000/auth/me \
  -H 'Authorization: Bearer <tu_token_aqui>'

```

### Logout

```bash
curl -X POST http://localhost:5000/auth/logout \
  -H 'Authorization: Bearer <tu_token_aqui>' \
  -H 'Content-Type: application/json'
```

### Si protejo la ruta de añadir un nuevo producto a la base de datos:

En `blueprints/productos.py`

```bash
from flask_jwt_extended import jwt_required  # Añadir esta importación

...

# POST - Crear nuevo producto
@productos_bp.route('/productos', methods=['POST'])
@jwt_required() ### <---- Añadir el decorador aquí
def crear_producto():
    try:
        ...
```

…y tendré que hacer la petición POST así (poniéndole el token):

```bash
curl -X POST http://localhost:5000/api/productos \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <tu_token_jwt_aqui>" \
  -d '{
    "nombre": "Teclado Mecánico",
    "precio": 75.5,
    "descripcion": "Teclado gaming con switches azules",
    "categoria": "Periféricos",
    "stock": 10
  }'
```