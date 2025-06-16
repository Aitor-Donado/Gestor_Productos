from flask import Flask
from extensions import db, migrate
from extensions import bcrypt, jwt


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
    
    from blueprints.productos import productos_bp
    from blueprints.auth import auth_bp
    # Registrar blueprints
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