from app import db

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