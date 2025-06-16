from flask import Blueprint, jsonify, request
from sqlalchemy.exc import SQLAlchemyError
from extensions import db
from models.producto import Producto

# Protección de rutas con JWT
from flask_jwt_extended import jwt_required



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
@jwt_required()
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