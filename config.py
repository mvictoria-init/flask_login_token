from decouple import config as env

class Config:
    
    JWT_SECRET_KEY = env('JWT_SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = env('SQLALCHEMY_DATABASE_URI')
    
    # blacklist
    JWT_BLACKLIST_ENABLED = True
    JWT_BLACKLIST_TOKEN_CHECKS = ['access', 'refresh']