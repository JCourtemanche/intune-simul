"""
Microsoft Graph subset used by the Exposure Management -> Intune remediation playbook.

Served under /v1.0/... and /beta/... (same behavior on both).
"""
from flask import Blueprint, jsonify, request

from auth import graph_error, require_bearer
from routes import _odata
from state import public, store

graph_bp = Blueprint('graph', __name__)

GRAPH_ROOT = 'https://graph.microsoft.com'


def _collection(ver, context, items):
    try:
        items = _odata.apply(items)
    except _odata.ODataError as e:
        return graph_error(400, 'BadRequest', str(e))
    return jsonify({'@odata.context': f'{GRAPH_ROOT}/{ver}/$metadata#{context}', 'value': items})


def _entity(ver, context, item):
    return jsonify({'@odata.context': f'{GRAPH_ROOT}/{ver}/$metadata#{context}/$entity', **item})


@graph_bp.before_request
def _refresh():
    store.refresh()


# ------------------------------------------------------------------ Intune managed devices
@graph_bp.route('/<any("v1.0", "beta"):ver>/deviceManagement/managedDevices', methods=['GET'])
@require_bearer
def list_managed_devices(ver):
    with store.lock:
        items = [public(d) for d in store.devices.values()]
    return _collection(ver, 'deviceManagement/managedDevices', items)


@graph_bp.route('/<any("v1.0", "beta"):ver>/deviceManagement/managedDevices/<device_id>', methods=['GET'])
@require_bearer
def get_managed_device(ver, device_id):
    with store.lock:
        device = store.devices.get(device_id)
        if not device:
            return graph_error(404, 'ResourceNotFound', f'Resource not found for the segment managedDevices.')
        return _entity(ver, 'deviceManagement/managedDevices', public(device))


@graph_bp.route('/<any("v1.0", "beta"):ver>/deviceManagement/managedDevices/<device_id>/syncDevice',
                methods=['POST'])
@require_bearer
def sync_device(ver, device_id):
    if device_id not in store.devices:
        return graph_error(404, 'ResourceNotFound', 'Resource not found for the segment managedDevices.')
    store.sync_device(device_id)
    return '', 204


# ------------------------------------------------------------------ Entra ID devices
@graph_bp.route('/<any("v1.0", "beta"):ver>/devices', methods=['GET'])
@require_bearer
def list_devices(ver):
    with store.lock:
        items = [public(e) for e in store.entra.values()]
    return _collection(ver, 'devices', items)


@graph_bp.route('/<any("v1.0", "beta"):ver>/devices/<object_id>', methods=['GET'])
@require_bearer
def get_device(ver, object_id):
    with store.lock:
        e = store.entra.get(object_id)
        if not e:
            return graph_error(404, 'Request_ResourceNotFound',
                               f"Resource '{object_id}' does not exist or one of its queried reference-property "
                               "objects are not present.")
        return _entity(ver, 'devices', public(e))


# ------------------------------------------------------------------ Groups
def _group_or_404(group_id):
    g = store.groups.get(group_id)
    if not g:
        return None, graph_error(404, 'Request_ResourceNotFound',
                                 f"Resource '{group_id}' does not exist or one of its queried reference-property "
                                 "objects are not present.")
    return g, None


@graph_bp.route('/<any("v1.0", "beta"):ver>/groups', methods=['GET'])
@require_bearer
def list_groups(ver):
    with store.lock:
        items = [public(g) for g in store.groups.values()]
    return _collection(ver, 'groups', items)


@graph_bp.route('/<any("v1.0", "beta"):ver>/groups/<group_id>', methods=['GET'])
@require_bearer
def get_group(ver, group_id):
    with store.lock:
        g, err = _group_or_404(group_id)
        return err or _entity(ver, 'groups', public(g))


@graph_bp.route('/<any("v1.0", "beta"):ver>/groups/<group_id>/members', methods=['GET'])
@require_bearer
def list_members(ver, group_id):
    with store.lock:
        g, err = _group_or_404(group_id)
        if err:
            return err
        items = [{'@odata.type': '#microsoft.graph.device', **public(store.entra[e])} for e in store.members[group_id]]
    return _collection(ver, 'directoryObjects', items)


@graph_bp.route('/<any("v1.0", "beta"):ver>/groups/<group_id>/members/$ref', methods=['POST'])
@require_bearer
def add_member(ver, group_id):
    g, err = _group_or_404(group_id)
    if err:
        return err
    body = request.get_json(silent=True) or {}
    ref = body.get('@odata.id', '')
    if not ref:
        return graph_error(400, 'Request_BadRequest', "Missing '@odata.id' in request body.")
    object_id = ref.rstrip('/').split('/')[-1]
    result = store.add_member(group_id, object_id)
    if result == 'not_found':
        return graph_error(404, 'Request_ResourceNotFound',
                           f"Resource '{object_id}' does not exist or one of its queried reference-property "
                           "objects are not present.")
    if result == 'exists':
        return graph_error(400, 'Request_BadRequest',
                           "One or more added object references already exist for the following modified "
                           "properties: 'members'.")
    return '', 204


@graph_bp.route('/<any("v1.0", "beta"):ver>/groups/<group_id>/members/<object_id>/$ref', methods=['DELETE'])
@require_bearer
def remove_member(ver, group_id, object_id):
    g, err = _group_or_404(group_id)
    if err:
        return err
    if not store.remove_member(group_id, object_id):
        return graph_error(404, 'Request_ResourceNotFound',
                           f"Resource '{object_id}' does not exist or one of its queried reference-property "
                           "objects are not present.")
    return '', 204


# ------------------------------------------------------------------ Windows expedited quality updates
def _quality_profiles():
    profiles = []
    for g in store.groups.values():
        if g.get('_remediation') != 'windows':
            continue
        profiles.append({
            'id': f'{g["id"][:8]}-qu00-4000-8000-expedite0001',
            'displayName': g['_policy'],
            'description': 'Expedites the latest Windows security update for devices flagged by Cortex XSIAM '
                           'Exposure Management.',
            'expeditedUpdateSettings': {'qualityUpdateRelease': '2024-08-13T00:00:00Z', 'daysUntilForcedReboot': 1},
            'releaseDateDisplayName': 'August 13, 2024 - 2024.08 B Security Updates for Windows 10 and later',
            'deployableContentDisplayName': 'Quality Updates for Windows 10 and later',
            'createdDateTime': g['createdDateTime'], 'lastModifiedDateTime': g['createdDateTime'],
            'roleScopeTagIds': ['0'],
            '_group': g['id'],
        })
    return profiles


@graph_bp.route('/<any("v1.0", "beta"):ver>/deviceManagement/windowsQualityUpdateProfiles', methods=['GET'])
@require_bearer
def list_quality_profiles(ver):
    with store.lock:
        items = [public(p) for p in _quality_profiles()]
    return _collection(ver, 'deviceManagement/windowsQualityUpdateProfiles', items)


@graph_bp.route('/<any("v1.0", "beta"):ver>/deviceManagement/windowsQualityUpdateProfiles/<profile_id>/assignments',
                methods=['GET'])
@require_bearer
def list_quality_profile_assignments(ver, profile_id):
    with store.lock:
        p = next((p for p in _quality_profiles() if p['id'] == profile_id), None)
        if not p:
            return graph_error(404, 'ResourceNotFound', 'Resource not found for the segment windowsQualityUpdateProfiles.')
        items = [{'id': f'{profile_id}_{p["_group"]}',
                  'target': {'@odata.type': '#microsoft.graph.groupAssignmentTarget', 'groupId': p['_group']}}]
    return _collection(ver, 'deviceManagement/windowsQualityUpdateProfiles/assignments', items)
