#!/usr/bin/env python3
"""flask app
"""
from flask import Flask, request, jsonify, abort, redirect, Response
from auth import Auth
from sqlalchemy.orm.exc import NoResultFound


AUTH = Auth()

app = Flask(__name__)


@app.route('/', methods=['GET'])
def index():
    """route to
    """
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'])
def users():
    """register user
    """
    try:
        AUTH.register_user(request.form['email'],
                           request.form['password'])
        return jsonify({"email": request.form['email'],
                        "message": "user created"})
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route('/sessions', methods=['POST'])
def login():
    """login
    """
    if AUTH.valid_login(request.form['email'], request.form['password']):
        session_id = AUTH.create_session(request.form['email'])
        resp = jsonify({"email": request.form['email'],
                        "message": "logged in"})
        resp.set_cookie("session_id", session_id)
        return resp
    abort(401)


@app.route('/sessions', methods=['DELETE'])
def logout():
    """logout
    """
    session_id = request.cookies.get('session_id')
    usr = AUTH.get_user_from_session_id(session_id)
    if usr:
        AUTH.destroy_session(usr.id)
        return redirect('/')
    abort(403)


@app.route('/profile', methods=['GET'])
def profile():
    """profile route
    """
    session_id = request.cookies.get('session_id')
    usr = AUTH.get_user_from_session_id(session_id)
    if usr:
        return jsonify({"email": usr.email}), 200
    abort(403)


@app.route('/reset_password', methods=['POST'])
def get_reset_password_token():
    """get reset password token
    """
    try:
        reset_token = AUTH.get_reset_password_token(request.form['email'])
        return jsonify({"email": request.form['email'],
                        "reset_token": reset_token}), 200
    except ValueError:
        abort(403)


@app.route('/reset_password', methods=['PUT'])
def update_password():
    """update password
    """
    try:
        AUTH.update_password(request.form['reset_token'],
                             request.form['new_password'])
        return jsonify({"email": request.form['email'],
                        "message": "Password updated"}), 200
    except ValueError:
        abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
