from flask import Flask, request, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pydantic import BaseModel, EmailStr, ValidationError
import re
import logging
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# Configuración del sistema de alertas
logging.basicConfig(filename='security.log', level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuración de Flask-Limiter para limitar el número de solicitudes
limiter = Limiter(get_remote_address)

class SQLInjectionDetector:
    def __init__(self):
        self.patterns = [
            r"(\bor\b|\band\b)",     # Condiciones lógicas
            r"(--|\#)",               # Comentarios SQL
            r"(\bunion\b|\bselect\b)",# Keywords peligrosas
            r"(\bdrop\b|\bdelete\b)", # Manipulación directa de datos
            r";",                     # Final de consulta
        ]
    
    def check_for_injection(self, user_input):
        for pattern in self.patterns:
            if re.search(pattern, user_input, re.IGNORECASE):
                logging.warning(f"Posible intento de inyección SQL detectado: {user_input}")
                return True
        return False

class DatabaseManager:
    def __init__(self, app):
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
        app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        self.db = SQLAlchemy(app)
        
        class User(self.db.Model):
            id = self.db.Column(self.db.Integer, primary_key=True)
            username = self.db.Column(self.db.String(50), unique=True, nullable=False)
            email = self.db.Column(self.db.String(120), unique=True, nullable=False)
            password_hash = self.db.Column(self.db.String(128))

        self.User = User
        with app.app_context():
            self.db.create_all()

    def add_user(self, username, email, password):
        try:
            password_hash = generate_password_hash(password)
            new_user = self.User(username=username, email=email, password_hash=password_hash)
            self.db.session.add(new_user)
            self.db.session.commit()
            return True, "Usuario añadido correctamente"
        except Exception as e:
            logging.warning("Error en la base de datos: %s", e)
            self.db.session.rollback()
            return False, "No se pudo añadir el usuario"

    def get_user(self, user_id):
        return self.User.query.get(user_id)

    def authenticate_user(self, username, password):
        user = self.User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            return True
        return False

class UserInput(BaseModel):
    username: str
    email: EmailStr
    password: str

class InjectionPreventionServer:
    def __init__(self):
        self.app = Flask(__name__)
        self.injection_detector = SQLInjectionDetector()
        self.db_manager = DatabaseManager(self.app)
        limiter.init_app(self.app)
        self.setup_routes()
    
    def setup_routes(self):
        def authenticate(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                auth = request.authorization
                if not auth or not self.db_manager.authenticate_user(auth.username, auth.password):
                    return jsonify({"status": "error", "message": "Autenticación requerida"}), 401
                return f(*args, **kwargs)
            return decorated

        @self.app.route('/add_user', methods=['POST'])
        @limiter.limit("5 per minute")  # Limita a 5 solicitudes por minuto
        def add_user():
            data = request.json
            try:
                user_data = UserInput(**data)
            except ValidationError as e:
                return jsonify({"status": "error", "message": str(e)}), 400

            if (self.injection_detector.check_for_injection(user_data.username) or 
                self.injection_detector.check_for_injection(user_data.email)):
                return jsonify({"status": "alert", "message": "Alerta: Intento de inyección SQL detectado."}), 400

            success, message = self.db_manager.add_user(user_data.username, user_data.email, user_data.password)
            status = "success" if success else "error"
            return jsonify({"status": status, "message": message})

        @self.app.route('/get_user/<int:user_id>', methods=['GET'])
        @authenticate
        def get_user(user_id):
            user = self.db_manager.get_user(user_id)
            if user:
                return jsonify({"status": "success", "user": {"username": user.username, "email": user.email}})
            else:
                return jsonify({"status": "error", "message": "Usuario no encontrado"}), 404

    def run(self):
        self.app.run(host="0.0.0.0", port=5000)  # Habilitar HTTPS en producción

if __name__ == "__main__":
    server = InjectionPreventionServer()
    server.run()
