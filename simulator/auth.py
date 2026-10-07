"""
Entra ID client-credentials flow, as used by the Cortex Microsoft integrations.

Token endpoint: POST /<tenant_id>/oauth2/v2.0/token (form: client_id, client_secret,
grant_type=client_credentials, scope). Graph calls then carry `Authorization: Bearer <token>`.

Tokens are stateless (HMAC-signed) so they survive a container restart.
"""
import base64
import hashlib
import hmac
import time
from functools import wraps

from flask import jsonify, request

from config import Config


def _sign(payload):
    return hmac.new(Config.CLIENT_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()


def issue_token():
    exp = int(time.time()) + Config.TOKEN_LIFETIME
    payload = f'{Config.CLIENT_ID}|{exp}'
    raw = f'{payload}|{_sign(payload)}'
    return base64.urlsafe_b64encode(raw.encode()).decode().rstrip('=')


def token_is_valid(token):
    try:
        raw = base64.urlsafe_b64decode(token + '=' * (-len(token) % 4)).decode()
        client_id, exp, sig = raw.split('|')
    except Exception:
        return False
    payload = f'{client_id}|{exp}'
    return (hmac.compare_digest(sig, _sign(payload))
            and client_id == Config.CLIENT_ID
            and int(exp) > time.time())


def graph_error(status, code, message):
    return jsonify({'error': {
        'code': code,
        'message': message,
        'innerError': {'date': time.strftime('%Y-%m-%dT%H:%M:%S'), 'request-id': 'intune-simulator'},
    }}), status


def require_bearer(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        header = request.headers.get('Authorization', '')
        if not header.lower().startswith('bearer ') or not token_is_valid(header[7:].strip()):
            return graph_error(401, 'InvalidAuthenticationToken', 'Access token is empty or invalid.')
        return f(*args, **kwargs)
    return decorated
