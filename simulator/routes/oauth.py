"""Entra ID token endpoint (client credentials)."""
from flask import Blueprint, jsonify, request

from auth import issue_token
from config import Config

oauth_bp = Blueprint('oauth', __name__)


def _aad_error(status, error, code, description):
    return jsonify({'error': error, 'error_description': f'{code}: {description}',
                    'error_codes': [int(code[len('AADSTS'):])], 'trace_id': 'intune-simulator'}), status


@oauth_bp.route('/<tenant_id>/oauth2/v2.0/token', methods=['POST'])
@oauth_bp.route('/<tenant_id>/oauth2/token', methods=['POST'])
def token(tenant_id):
    form = request.form
    if tenant_id not in (Config.TENANT_ID, 'organizations', 'common'):
        return _aad_error(400, 'invalid_request', 'AADSTS90002', f"Tenant '{tenant_id}' not found.")
    if form.get('grant_type') != 'client_credentials':
        return _aad_error(400, 'unsupported_grant_type', 'AADSTS70003',
                          'The simulator only supports the client_credentials grant.')
    if form.get('client_id') != Config.CLIENT_ID:
        return _aad_error(400, 'unauthorized_client', 'AADSTS700016',
                          f"Application with identifier '{form.get('client_id')}' was not found.")
    if form.get('client_secret') != Config.CLIENT_SECRET:
        return _aad_error(401, 'invalid_client', 'AADSTS7000215', 'Invalid client secret provided.')
    return jsonify({'token_type': 'Bearer', 'expires_in': Config.TOKEN_LIFETIME,
                    'ext_expires_in': Config.TOKEN_LIFETIME, 'access_token': issue_token()})
