"""
View functions for user authorisation, including password reset by email
"""
import os
import json
from flask import render_template, request, redirect, url_for, flash
from flask_login import current_user, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash
from werkzeug.urls import url_parse

from app import db
from app.auth import bp
from app.models import User
from app.auth.email import send_password_reset_email, send_login_email

import logging
logger = logging.getLogger(__name__)

@bp.route("/login", methods=["GET", "POST"])
def login():
	if request.method == 'POST':
		if current_user.is_authenticated:
			return redirect(url_for('main.index'))
		user = User.query.filter_by(username=request.form['username']).first()
		if user is None or not user.check_password(request.form['password']):
			flash('Invalid username or password', 'danger')
			return redirect(url_for('auth.login'))
		try:
			r = bool(request.form['remember'])
		except KeyError:
			r = False
		login_user(user, remember=r)
		next_page = request.args.get('next')
		if not next_page or url_parse(next_page).netloc != '':
			next_page = url_for('main.index')
		return redirect(next_page)

	return render_template('login.html')

@bp.route("/login-by-email", methods=["GET", "POST"])
def login_by_email():
	if request.method == 'POST':
		if current_user.is_authenticated:
			return redirect(url_for('main.index'))
		user = User.query.filter_by(username=request.form['username']).first()
		if user is None:
			flash('Email address not recognised', 'danger')
			return redirect(url_for('auth.login_by_email'))
		try:
			r = bool(request.form['remember'])
		except KeyError:
			r = False
		# send magic link by email
		send_login_email(user)
		flash('Please check your email for a link to sign in',
					 'success')
		return redirect(url_for('main.index'))
	token = request.args.get('token')
	if token:
		user = User.verify_token(request.args['token'], 'login')
		# commit session to update update active token record in user object
		db.session.commit()
		if not user:
			flash('Invalid sign in link', 'danger')
			return redirect(url_for('auth.login_by_email'))
		login_user(user, remember=True)
		next_page = request.args.get('next')
		if not next_page or url_parse(next_page).netloc != '':
			next_page = url_for('main.index')
		return redirect(next_page)
	return render_template('login_by_email.html')

@bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('main.index'))

@bp.route('/reset_password_request', methods=["GET", "POST"])
def reset_password_request():
	if request.method == "POST":
		user = User.query.filter_by(username=request.form['email']).first()
		if user:
			send_password_reset_email(user)
		flash('Please check your email for instructions on resetting your password',
					 'success')
	if current_user.is_authenticated:
		return redirect(url_for('main.index'))
	return render_template('reset_password_request.html')

@bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
	if current_user.is_authenticated:
		return redirect(url_for('main.index'))
	user = User.verify_token(token, 'reset_password')
	if not user:
		return redirect(url_for('main.index'))
	if request.method == "POST":
		user.set_password(request.form['password'])
		db.session.commit()
		flash('Your password has been reset.', 'success')
		return redirect(url_for('auth.login'))
	return render_template('reset_password.html')
