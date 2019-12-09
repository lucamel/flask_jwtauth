# -*- coding: utf-8 -*-
'''
    flask_jwtauth
    ~~~~~~~~~

    Flask-JWTAuth module
'''
import uuid

from functools import wraps

import jwt

from datetime import datetime, timedelta

from flask import current_app, _app_ctx_stack, request, jsonify, _request_ctx_stack, abort
from werkzeug.local import LocalProxy

__title__ = 'Flask-JWTAuth'
__version__ = '0.1'
__author__ = 'Luca Melgrati'
__license__ = 'BSD'
__copyright__ = 'Copyright 2019 Luca Melgrati'

_jwtauth = LocalProxy(lambda: current_app.extensions['jwtauth'])

current_user = LocalProxy(lambda: getattr(_request_ctx_stack.top, 'current_user', None))

CONFIG_DEFAULTS = {
    'JWTAUTH_AUTH_URL': '/authorize',
    'JWTAUTH_REFRESH_URL': '/refresh',
    'JWTAUTH_TOKEN_TYPE': 'JWT',
    'JWTAUTH_USERNAME_KEY': 'username',
    'JWTAUTH_PASSWORD_KEY': 'password',
    'JWTAUTH_ALGORITHM': 'HS256',
    'JWTAUTH_AUTH_URL_METHODS': 'POST',
    'JWTAUTH_REFRESH_URL_METHODS': 'POST',
    'JWTAUTH_USER_ID_FIELDS': 'id',
    'JWTAUTH_DEFAULT_REALM': 'Login Required',
    'JWTAUTH_LEEWAY': timedelta(seconds=10),
    'JWTAUTH_ACEESS_TOKEN_EXPIRATION_DELTA': timedelta(hours=1),
    'JWTAUTH_ACEESS_TOKEN_NOT_BEFORE_DELTA': timedelta(seconds=0),
    'JWTAUTH_REFRESH_TOKEN_EXPIRATION_DELTA': timedelta(days=30),
    'JWTAUTH_REFRESH_TOKEN_NOT_BEFORE_DELTA': timedelta(seconds=0),
    'JWTAUTH_VERIFY_CLAIMS': ['signature', 'exp', 'nbf', 'iat'],
    'JWTAUTH_REQUIRED_CLAIMS': ['exp', 'iat', 'nbf']
}

def _default_auth_request_handler():
    data = request.get_json()
    username = data.get(current_app.config.get('JWTAUTH_USERNAME_KEY'), None)
    password = data.get(current_app.config.get('JWTAUTH_PASSWORD_KEY'), None)
    criterion = [username, password, len(data) == 2]

    if not all(criterion):
        raise JWTAuthError(message='Invalid credentials')

    user = _jwtauth.authentication_callback(username, password)
    if user:
        access_token = _jwtauth.access_token_encode_callback(user)
        refresh_token = _jwtauth.refresh_token_encode_callback()
        return _jwtauth.auth_response_callback(access_token, refresh_token, user)
    else:
        raise JWTAuthError(message='Invalid Credentials')

def _default_auth_response_handler(access_token, refresh_token, user):
    exp = int(current_app.config.get('JWTAUTH_ACEESS_TOKEN_EXPIRATION_DELTA').total_seconds())
    return jsonify({'access_token': access_token.decode('utf-8'),
    'expires_in': exp,
    'refresh_token': refresh_token.decode('utf-8'),
    'token_type': current_app.config.get('JWTAUTH_TOKEN_TYPE')
    })

def _default_refresh_request_handler():
    data = request.get_json()
    token = data.get('refresh_token', None)

    if token is None:
        raise JWTAuthError('InvalidRequest', 'Refresh token missing')

    try:
        payload = _jwtauth.access_token_decode_callback(token)
    except jwt.InvalidTokenError as e:
        raise JWTAuthError('InvalidToken', str(e))

    user = _jwtauth.refresh_callback(payload)
    if user:
        access_token = _jwtauth.access_token_encode_callback(user)
        refresh_token = _jwtauth.refresh_token_encode_callback()
        return _jwtauth.refresh_response_callback(access_token, refresh_token, user)
    else:
        raise JWTAuthError(message='Invalid Credentials')

def _default_refresh_response_handler(access_token, refresh_token, user):
    return _jwtauth.auth_response_callback(access_token, refresh_token, user)


def _default_access_token_payload_handler(user):
    iat = datetime.utcnow()
    exp = iat + current_app.config.get('JWTAUTH_ACEESS_TOKEN_EXPIRATION_DELTA')
    nbf = iat + current_app.config.get('JWTAUTH_ACEESS_TOKEN_NOT_BEFORE_DELTA')
    user = getattr(user, current_app.config.get('JWTAUTH_USER_ID_FIELDS')) or user[current_app.config.get('JWTAUTH_USER_ID_FIELDS')]
    return {'exp': exp, 'iat': iat, 'nbf': nbf, 'user': user}

def _default_access_token_encode_handler(user):
    secret = current_app.config['JWTAUTH_SECRET_KEY']
    algorithm = current_app.config['JWTAUTH_ALGORITHM']
    headers = None

    payload = _jwtauth.access_token_payload_callback(user)
    
    return jwt.encode(payload, secret, algorithm=algorithm, headers=headers)

def _default_access_token_decode_handler(token):
    secret = current_app.config['JWTAUTH_SECRET_KEY']
    algorithm = current_app.config['JWTAUTH_ALGORITHM']
    leeway = current_app.config['JWTAUTH_LEEWAY']

    verify_claims = current_app.config['JWTAUTH_VERIFY_CLAIMS']
    required_claims = current_app.config['JWTAUTH_REQUIRED_CLAIMS']

    options = {
        'verify_' + claim: True
        for claim in verify_claims
    }

    options.update({
        'require_' + claim: True
        for claim in required_claims
    })

    return jwt.decode(token, secret, options=options, algorithms=[algorithm], leeway=leeway)    


def _default_refresh_token_payload_handler():
    iat = datetime.utcnow()
    exp = iat + current_app.config.get('JWTAUTH_REFRESH_TOKEN_EXPIRATION_DELTA')
    nbf = iat + current_app.config.get('JWTAUTH_REFRESH_TOKEN_NOT_BEFORE_DELTA')
    return {'exp': exp, 'iat': iat, 'nbf': nbf, 'id': str(uuid.uuid1())}

def _default_refresh_token_encode_handler():
    secret = current_app.config['JWTAUTH_SECRET_KEY']
    algorithm = current_app.config['JWTAUTH_ALGORITHM']
    headers = None

    payload = _jwtauth.refresh_token_payload_callback()
    
    return jwt.encode(payload, secret, algorithm=algorithm, headers=headers)

def _default_refresh_token_decode_handler():
    return


def _default_request_handler():
    auth_header_value = request.headers.get('Authorization', None)
    auth_header_prefix = current_app.config['JWTAUTH_TOKEN_TYPE']

    if not auth_header_value:
        return

    parts = auth_header_value.split()

    if parts[0].lower() != auth_header_prefix.lower():
        raise JWTAuthError('InvalidJWTHeader', 'Unsupported authorization type')
    elif len(parts) == 1:
        raise JWTAuthError('InvalidJWTHeader', 'Token missing')
    elif len(parts) > 2:
        raise JWTAuthError('InvalidJWTHeader', 'Token contains spaces')

    return parts[1]    

def _default_jwtauth_error_handler(error):
    e = {
        'error': {
            'message' : error.message,
            'type' : error.type,
            }
        }
    if error.payload is not None:
        e['error'].update(error.payload)
    return jsonify(e), error.status_code, error.headers


def _jwtauth_required(realm):
    """Does the actual work of verifying the JWT data in the current request.
    This is done automatically for you by `jwt_required()` but you could call it manually.
    Doing so would be useful in the context of optional JWT access in your APIs.

    :param realm: an optional realm
    """
    token = _jwtauth.request_callback()

    if token is None:
        raise JWTAuthError( error='AuthorizationRequired', message='Request does not contain an access token',
                       headers={'WWW-Authenticate': 'JWT realm="%s"' % realm})

    try:
        payload = _jwtauth.access_token_decode_callback(token)
    except jwt.InvalidTokenError as e:
        raise JWTAuthError('InvalidToken', str(e))

    _request_ctx_stack.top.current_user = user = _jwtauth.user_callback(payload)

    if user is None:
        raise JWTAuthError('InvalidJWT', 'User does not exist')


def jwtauth_required(realm=None):
    """View decorator that requires a valid JWT token to be present in the request

    :param realm: an optional realm
    """
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            _jwtauth_required(realm or current_app.config['JWTAUTH_DEFAULT_REALM'])
            return fn(*args, **kwargs)
        return decorator
    return wrapper


class JWTAuthError(Exception):
    def __init__(self, error='InvalidRequest', message=None, status_code=401, payload=None, headers=None):
        Exception.__init__(self)
        self.message = message
        self.status_code = status_code
        self.type = error
        self.payload = payload
        self.headers = headers

    def to_dict(self):
        rv = dict(self.payload or ())
        rv['message'] = self.message
        return rv


class JWTAuth(object):
    def __init__(self, app=None, authentication_handler=None, user_handler=None, refresh_handler=None):
        self.authentication_callback = authentication_handler
        self.user_callback = user_handler
        self.refresh_callback = refresh_handler

        self.auth_request_handler = _default_auth_request_handler
        self.auth_response_callback = _default_auth_response_handler
        self.refresh_request_handler = _default_refresh_request_handler
        self.refresh_response_callback = _default_refresh_response_handler

        self.access_token_payload_callback = _default_access_token_payload_handler
        self.access_token_encode_callback = _default_access_token_encode_handler
        self.access_token_decode_callback = _default_access_token_decode_handler

        self.refresh_token_payload_callback = _default_refresh_token_payload_handler
        self.refresh_token_encode_callback = _default_refresh_token_encode_handler
        self.refresh_token_decode_callback = _default_refresh_token_decode_handler

        self.request_callback = _default_request_handler
        self.jwtauth_error_callback = _default_jwtauth_error_handler

        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        for k, v in CONFIG_DEFAULTS.items():
            app.config.setdefault(k, v)
        app.config.setdefault('JWTAUTH_SECRET_KEY', app.config['SECRET_KEY'])

        auth_url_rule = app.config.get('JWTAUTH_AUTH_URL', None)
        auth_url_options = {'methods': app.config.get('JWTAUTH_AUTH_URL_METHODS', None).split(',')}
        auth_url_options.setdefault('view_func', self.auth_request_handler)
        app.add_url_rule(auth_url_rule, **auth_url_options)

        refresh_url_rule = app.config.get('JWTAUTH_REFRESH_URL', None)
        refresh_url_options = {'methods': app.config.get('JWTAUTH_REFRESH_URL_METHODS', None).split(',')}
        refresh_url_options.setdefault('view_func', self.refresh_request_handler)
        app.add_url_rule(refresh_url_rule, **refresh_url_options)

        app.errorhandler(JWTAuthError)(self._jwtauth_error_callback)

        if not hasattr(app, 'extensions'):  # pragma: no cover
            app.extensions = {}

        app.extensions['jwtauth'] = self

    def request_handler(self, callback):
        """Specifieds the request handler function. This function returns a JWT from the current
        request.

        :param callable callback: the request handler function
        """
        self.request_callback = callback
        return callback

    def _jwtauth_error_callback(self, error):
        return self.jwtauth_error_callback(error)

    def jwtauth_access_token_payload_handler(self, callback):
        self.access_token_payload_callback = callback
        return callback

    def jwtauth_refresh_token_payload_handler(self, callback):
        self.refresh_token_payload_callback = callback
        return callback