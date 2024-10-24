from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt

from app import db, jwt
from .model import User

bp = Blueprint('auth', __name__, url_prefix = '/api/auth')

revoked_tokens = set()

# check if a JWT token has been revoked
@jwt.token_in_blocklist_loader
def check_if_token_in_blacklist(jwt_header, jwt_payload):
        jti = jwt_payload['jti']
        return jti in revoked_tokens

@bp.route('/register', methods=['POST'])
def register_user():
    
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}),
    
    data = request.get_json()
    
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    confirm_password = data.get('confirmpassword')
    
    user_email = User.query.filter_by(email = email).first()
    
    if user_email == None:
        
        if not username or not password or not confirm_password:
            return jsonify({"msg": "Username and passwords are required"}), 400

        if password != confirm_password:
            return jsonify({"msg": "Passwords do not match"}), 400
        
        new_user = User(username=username, email=email, password=generate_password_hash(password))
    
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"msg": "User registered successfully"}), 201

    else:
        return jsonify({"msg": "The email is already in use, please try another email."}), 307

@bp.route('/login', methods=['GET', 'POST'])
def login_user():
    
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}),

    if request.method == 'POST':
        data = request.get_json()
        email = data.get('email', None)
        password = data.get('password', None)
        
        normalized_email = email.lower()

        user = User.query.filter_by(email =  normalized_email).first()
    
        if user == None or not check_password_hash(user.password, password):
            return jsonify({"msg": "Bad username or password"}), 401
        
        else:
            access_token = create_access_token(identity=email)
            return jsonify(token=access_token), 200
    
    return jsonify({"msg": "Invalid credentials"}), 401

@bp.route('/logout', methods=['GET'])
@jwt_required()
def logout_user():
    jti = get_jwt()['jti']
    revoked_tokens.add(jti)
    return jsonify({"msg": "Successfully logged out"}), 200
        
    
@bp.route('/hola', methods=['GET'])
@jwt_required()
def hola():
    return jsonify({"msg": "holis"}), 200