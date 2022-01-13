#!/usr/bin/env python3
"""Session Expiration module
"""
from api.v1.auth.session_auth import SessionAuth
from os import getenv
from datetime import datetime


class SessionExpAuth(SessionAuth):
    """Session Expiration class
    """
    user_id_by_session_id = {}

    def __init__(self):
        sd = getenv("SESSION_DURATION", None)
        if not sd:
            self.session_duration = 0
        else:
            try:
                self.session_duration = int(sd)
            except Exception:
                self.session_duration = 0

    def create_session(self, user_id=None):
        """Create session
        """
        session_id = super().create_session(user_id)
        if not session_id:
            return None
        session_dictionary = {}
        session_dictionary["user_id"] = user_id
        session_dictionary["created_at"] = datetime.now()
        SessionExpAuth.user_id_by_session_id[session_id] = session_dictionary
        return session_id

    def user_id_for_session_id(self, session_id=None):
        """return user_id of session_id
        """
        if session_id is None:
            return None
        session_dict = SessionExpAuth.user_id_by_session_id.get(session_id)
        if not session_dict:
            return None
        if self.session_duration <= 0:
            return session_dict.get("user_id")
        created_at = session_dict.get("created_at")
        if not created_at:
            return None
        elapsed_time = (datetime.now() - created_at).total_seconds()
        if elapsed_time > self.session_duration:
            return None
        return session_dict.get("user_id")
