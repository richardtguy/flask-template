"""
Database model definitions
"""
from flask import current_app
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from time import time
import jwt
import logging
import uuid
from app import db, login

logger = logging.getLogger(__name__)

@login.user_loader
def load_user(id):
    return User.query.get(int(id))

class User(UserMixin, db.Model):
    """
    Database model for user accounts
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    active_token = db.Column(db.String(36))

    def set_password(self, password):
    	self.password_hash = generate_password_hash(password)

    def check_password(self, password):
    	return check_password_hash(self.password_hash, password)

    def get_token(self, scope, unique=None, expires_in=600):
        token = {scope: self.id, 'exp': time() + expires_in}
        if unique:
            id = uuid.uuid4().hex
            self.active_token = id
            token['token_id'] = id
        return jwt.encode(token, current_app.config['SECRET_KEY'], algorithm='HS256')

    @staticmethod
    def verify_token(token, scope):
        # verify signed token has the given scope and is active
        user = None
        try:
            token = jwt.decode(token, current_app.config['SECRET_KEY'],
            								algorithms=['HS256'])
            id = token.get(scope)
            user = User.query.get(id)
            if not user.active_token or (token.get('token_id') != user.active_token):
                return None
        except:
            return None
        user.active_token = ''
        return user

    def __repr__(self):
    	return '<User {}>'.format(self.username)
