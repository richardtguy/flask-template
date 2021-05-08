"""
Database model definitions
"""
from flask import current_app
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from time import time
import jwt
import logging
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

	def set_password(self, password):
		self.password_hash = generate_password_hash(password)

	def check_password(self, password):
		return check_password_hash(self.password_hash, password)

	def get_token(self, name, expires_in=600):
		return jwt.encode({name: self.id, 'exp': time() + expires_in},
			current_app.config['SECRET_KEY'], algorithm='HS256')

	@staticmethod
	def verify_token(token, scope):
		try:
			id = jwt.decode(token, current_app.config['SECRET_KEY'],
											algorithms=['HS256'])[scope]
		except:
			return None
		return User.query.get(id)

	def __repr__(self):
		return '<User {}>'.format(self.username)
