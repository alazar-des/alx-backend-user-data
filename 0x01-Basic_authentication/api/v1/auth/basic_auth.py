#!/usr/bin/env python3
"""Basic Auth implementation
"""

from api.v1.auth.auth import Auth
from models.user import User
import base64
from typing import TypeVar


class BasicAuth(Auth):
    """Basic Auth
    """
    def extract_base64_authorization_header(
            self, authorization_header: str) -> str:
        """ extract base64 of authorization header after "Basic "
        """
        if authorization_header is None or type(authorization_header) != str:
            return None
        if not authorization_header.startswith("Basic "):
            return None
        return authorization_header.split("Basic ")[1]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """ return base64 of string
        """
        if base64_authorization_header is None or \
           type(base64_authorization_header) != str:
            return None

        try:
            return base64.b64decode(base64_authorization_header).\
                decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> (str, str):
        """ extract user credentials
        """
        if decoded_base64_authorization_header is None or\
           type(decoded_base64_authorization_header) != str:
            return (None, None)

        if ":" not in decoded_base64_authorization_header:
            return (None, None)

        return (decoded_base64_authorization_header.split(":")[0],
                decoded_base64_authorization_header.split(":")[1])

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """ return User instance based on the email and password
        """
        if user_email is None or type(user_email) != str:
            return None
        if user_pwd is None or type(user_pwd) != str:
            return None

        obj = User.search({'email': user_email})
        if obj:
            if obj[0].is_valid_password(user_pwd):
                return obj[0]
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """retrieves the User instance for a request
        """
        credential = self.authorization_header(request)
        extr = self.extract_base64_authorization_header(credential)
        decd = self.decode_base64_authorization_header(extr)
        user_crd = self.extract_user_credentials(decd)
        return self.user_object_from_credentials(user_crd[0], user_crd[1])
