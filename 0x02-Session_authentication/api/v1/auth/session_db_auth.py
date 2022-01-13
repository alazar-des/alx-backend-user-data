#!/usr/bin/env python3
""" Session db auth module
"""
from api.v1.auth.session_exp_auth import SessionExpAuth
from models.user_session import UserSession
from flask import abort


class SessionDBAuth(SessionExpAuth):
    """SessionDBAuth class
    """

    def create_session(self, user_id=None):
        """creates and stores new instance of UserSession
        """
        session_id = super().create_session(user_id)
        if not session_id:
            return None
        kwargs = {'session_id': session_id, 'user_id': user_id}
        us = UserSession(**kwargs)
        us.save()
        return session_id

    def user_id_for_session_id(self, session_id=None):
        """request user_id from db based on session_id
        """
        if session_id is None or type(session_id) != str:
            return None
        obj = UserSession.search({"session_id": session_id})
        if obj:
            return obj[0].user_id
        return None

    def destroy_session(self, request=None):
        """Distroy session based on session_id
        """
        if request is None:
            return False
        session_id = self.session_cookie(request)
        if not session_id:
            return False
        obj = UserSession.search({"session_id": session_id})
        if obj:
            obj[0].remove()
            return True
        return False
