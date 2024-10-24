from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt

app = Flask(__name__)

app.config['JWT_SECRET_KEY'] = ''
app.config["SQLALCHEMY_DATABASE_URI"] = ''

# blacklist
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']

db = SQLAlchemy(app)
jwt = JWTManager(app)

revoked_tokens = set()

# check if a JWT token has been revoked
@jwt.token_in_blocklist_loader
def check_if_token_in_blacklist(jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    return jti in revoked_tokens

# create models of db 
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(50), nullable=False)
    
    def serialize(self):
        return {
            'id' : self.id,
            'name' : self.username,
            'email' : self.email,
        }

# create table
with app.app_context():
    db.create_all()
    
@app.route('/register', methods=['POST'])
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

@app.route('/login', methods=['GET', 'POST'])
def login_user():
    
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}),

    if request.method == 'POST':
        data = request.get_json()
        email = data.get('email', None)
        password = data.get('password', None)
        
        normalized_email = email.lower()

        user = User.query.filter_by(email =  normalized_email).first()
        print(user)

        if user == None or not check_password_hash(user.password, password):
            return jsonify({"msg": "Bad username or password"}), 401
        
        else:
            access_token = create_access_token(identity=email)
            return jsonify(access_token=access_token), 200
    
    return jsonify({"msg": "Invalid credentials"}), 401

@app.route('/logout', methods=['GET'])
@jwt_required()
def logout_user():
    jti = get_jwt()['jti']
    revoked_tokens.add(jti)
    return jsonify({"msg": "Successfully logged out"}), 200
        
    
@app.route('/hola', methods=['GET'])
@jwt_required()
def hola():
    return jsonify({"msg": "holis"}), 200