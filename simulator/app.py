"""Microsoft Intune (Graph API) simulator - Flask entrypoint."""
import logging

from flask import Flask, jsonify

from config import Config
from routes.console import console_bp
from routes.graph import graph_bp
from routes.oauth import oauth_bp


def create_app():
    app = Flask(__name__)
    app.url_map.strict_slashes = False

    logging.basicConfig(
        level=logging.INFO if Config.DEBUG else logging.WARNING,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    )
    logger = logging.getLogger(__name__)
    logger.info('Starting Intune Graph API Simulator')

    app.register_blueprint(oauth_bp)
    app.register_blueprint(graph_bp)
    app.register_blueprint(console_bp)

    @app.route('/health', methods=['GET'])
    def health():
        return jsonify({
            'status': 'healthy',
            'service': 'Intune Graph API Simulator',
            'version': '1.0.0',
        }), 200

    @app.route('/', methods=['GET'])
    def root():
        return jsonify({
            'service': 'Intune Graph API Simulator',
            'version': '1.0.0',
            'auth': 'POST /<tenant_id>/oauth2/v2.0/token (client_credentials) then Authorization: Bearer <token>',
            'console': '/console',
            'endpoints': {
                'POST /<tenant_id>/oauth2/v2.0/token': 'Entra ID client credentials token',
                'GET /{v1.0|beta}/deviceManagement/managedDevices': "Intune devices ($filter=deviceName eq '...')",
                'GET /{v1.0|beta}/deviceManagement/managedDevices/<id>': 'Intune device (osVersion, complianceState)',
                'POST /{v1.0|beta}/deviceManagement/managedDevices/<id>/syncDevice': 'Force device check-in',
                'GET /{v1.0|beta}/devices': "Entra ID devices ($filter=deviceId eq '<azureADDeviceId>')",
                'GET /{v1.0|beta}/groups': "Entra ID groups ($filter=displayName eq '...')",
                'GET /{v1.0|beta}/groups/<id>/members': 'Group members',
                'POST /{v1.0|beta}/groups/<id>/members/$ref': 'Add a device to a group (starts remediation)',
                'DELETE /{v1.0|beta}/groups/<id>/members/<object_id>/$ref': 'Remove a device from a group',
                'GET /beta/deviceManagement/windowsQualityUpdateProfiles': 'Expedited Windows update profiles',
                'GET /console': 'Demo console (Intune-like live view)',
                'POST /console/api/reset': 'Reset the fleet to its initial state',
                'GET /health': 'Health check (no auth)',
            },
        }), 200

    @app.errorhandler(404)
    def not_found(_):
        return jsonify({'error': {'code': 'BadRequest', 'message': 'Resource not found for the segment.'}}), 404

    @app.errorhandler(500)
    def internal_error(error):
        logger.error(f'Internal server error: {error}')
        return jsonify({'error': {'code': 'InternalServerError', 'message': str(error)}}), 500

    return app


app = create_app()

if __name__ == '__main__':
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)
