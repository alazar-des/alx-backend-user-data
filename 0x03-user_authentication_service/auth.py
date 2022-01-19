#!/usr/bin/env python3
"""auth module
"""
import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
import uuid
from typing import TypeVar


def _hash_password(password: str) -> bytes:
    """ Encrypting passwords with bcrypt package
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def _generate_uuid() -> None:
    """generate uuid
    """
    return str(uuid.uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> TypeVar('User'):
        """Register user
        """
        try:
            self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists")
        except NoResultFound:
            return self._db.add_user(email, _hash_password(password))

    def valid_login(self, email: str, password: str) -> bool:
        """check if valid login
        """
        try:
            usr = self._db.find_user_by(email=email)
            return bcrypt.checkpw(password.encode('utf-8'),
                                  usr.hashed_password)
        except NoResultFound:
            return False

    def create_session(self, email: str) -> str:
        """create session id and store it in db
        """
        try:
            usr = self._db.find_user_by(email=email)
            session_id = _generate_uuid()
            self._db.update_user(usr.id, session_id=session_id)
            return session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> TypeVar('User'):
        """Get user from session id
        """
        if session_id is None:
            return None
        try:
            usr = self._db.find_user_by(session_id=session_id)
            return usr
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """Destroy session for user_id
        """
        try:
            self._db.update_user(user_id, session_id=None)
        except ValueError:
            pass

    def get_reset_password_token(self, email: str) -> str:
        """reset password
        """
        try:
            usr = self._db.find_user_by(email=email)
            reset_token = _generate_uuid()
            self._db.update_user(usr.id, reset_token=reset_token)
            return usr.reset_token
        except NoResultFound:
            raise ValueError

    def update_password(self, reset_token: str, password: str) -> None:
        """reset password
        """
        try:
            usr = self._db.find_user_by(reset_token=reset_token)
            self._db.update_user(usr.id,
                                 hashed_password=_hash_password(password))
            self._db.update_user(usr.id, reset_token=None)
        except NoResultFound:
            raise ValueError
