#!/usr/bin/env python3
"""
Main testing file
"""
from auth import Auth
import requests


auth = Auth()


def register_user(email: str, password: str) -> None:
    """test for auth.register_user
    """
    usr = auth.register_user(email, password)
    assert(usr.email == email)
    try:
        auth.register_user(email, password)
        assert False
    except ValueError:
        assert True


def log_in_wrong_password(email: str, password: str) -> None:
    """test with wrong password
    """
    payload = {'email': email, 'password': password}
    resp = requests.post('http://localhost:5000/sessions', data=payload)
    assert(resp.status_code == 401)


def log_in(email: str, password: str) -> str:
    """test with correct password
    """
    payload = {'email': email, 'password': password}
    session = requests.Session()
    resp = session.post('http://localhost:5000/sessions', data=payload)
    assert(resp.status_code == 200)
    cookies = session.cookies.get_dict()
    session_id = cookies.get('session_id')
    return session_id


def profile_unlogged() -> None:
    """logged with out session id
    """
    resp = requests.get('http://localhost:5000/profile')
    assert(resp.status_code == 403)


def profile_logged(session_id: str) -> None:
    """log with session id
    """
    cookies = dict(session_id=session_id)
    resp = requests.get('http://localhost:5000/profile', cookies=cookies)
    assert(resp.status_code == 200)


def log_out(session_id: str) -> None:
    """logout with session id
    """
    cookies = dict(session_id=session_id)
    resp = requests.delete('http://localhost:5000/sessions', cookies=cookies)
    assert(resp.history[0].status_code == 302)


def reset_password_token(email: str) -> str:
    """reset password token
    """
    payload = {'email': email}
    resp = requests.post('http://localhost:5000/reset_password', data=payload)
    reset_token = resp.json().get('reset_token')
    assert(type(reset_token) is str)
    return reset_token


def update_password(email: str, reset_token: str, new_password: str) -> None:
    """update password
    """
    payload = {'email': email,
               'reset_token': reset_token,
               'new_password': new_password}
    resp = requests.put('http://localhost:5000/reset_password', data=payload)
    assert(resp.status_code == 200)


EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"


if __name__ == "__main__":

    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
