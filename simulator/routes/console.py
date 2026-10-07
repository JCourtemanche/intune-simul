"""Demo console: an Intune-like view of the fleet, refreshed live during the demo."""
from flask import Blueprint, jsonify, render_template

from state import store

console_bp = Blueprint('console', __name__)


@console_bp.route('/console', methods=['GET'])
def console():
    return render_template('console.html')


@console_bp.route('/console/api/state', methods=['GET'])
def console_state():
    return jsonify(store.snapshot())


@console_bp.route('/console/api/reset', methods=['POST'])
def console_reset():
    store.reset()
    return jsonify({'status': 'reset'})
