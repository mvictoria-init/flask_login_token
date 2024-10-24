from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager

app = Flask(__name__)

app.config.from_object('config.Config')
 
db = SQLAlchemy(app)
jwt = JWTManager(app)

# Registrer views
from auth import views as lg
app.register_blueprint(lg.bp)

from auth.model import User

with app.app_context():
    db.create_all()


