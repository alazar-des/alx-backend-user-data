#!/usr/bin/env python3
""" Module of Session views
"""
from api.v1.views import app_views
from flask import jsonify, request
from models.user import User
from os import getenv
from api.v1.app import auth


@app_views.route('/auth_session/login', methods=["POST"], strict_slashes=False)
def login() -> str:
    """ POST /auth_session/login
    Return:
      -
    """
    email = request.form.get("email")
    if email is None or email == "":
        return jsonify({ "error": "email missing" }), 400
    pwd = request.form.get("password")
    if pwd is None or pwd == "":
        return jsonify({ "error": "password missing" }), 400
    user = User.search({'email': email})
    if not user:
        return jsonify({ "error": "no user found for this email" }), 404
    if not user[0].is_valid_password(pwd):
        return jsonify({ "error": "wrong password" }), 401
    else:
        from api.v1.app import auth
        session_id = auth.create_session(user[0].id)
        resp = jsonify(user[0].to_json(True))
        session_name = getenv("SESSION_NAME")
        resp.set_cookie(session_name, session_id)
        return resp


@app_views.route('/auth_session/logout', methods=["DELETE"],
                 strict_slashes=False)
def logout() -> str:
    """logout
    """
    if not auth.destroy_session(request):
        abort(404)
    return jsonify({}), 200
