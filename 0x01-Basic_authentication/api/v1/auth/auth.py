#!/usr/bin/env python3
"""template for all authentication system
"""

from flask import request
from typing import List, TypeVar
import re


class Auth:
    """ Auth template class
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """require athentication
        """
        if path is None or excluded_paths is None or not excluded_paths:
            return True
        if path in excluded_paths or path + "/" in excluded_paths:
            return False

        for ep in excluded_paths:
            if "*" in ep:
                pattern = "^" + ep
                if re.match(pattern, path):
                    return False
        return True

    def authorization_header(self, request=None) -> str:
        """authorization header
        """
        if request is not None:
            return request.headers.get('Authorization', None)
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """current user
        """
        return None
