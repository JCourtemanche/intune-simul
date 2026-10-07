"""
In-memory Intune state + patch engine.

The simulator must run as ONE process (gunicorn -w 1, Cloud Run max-instances 1),
otherwise each worker would hold its own fleet.

Patch lifecycle of a device added to a remediation group:
    assigned (waiting for check-in) -> downloading -> installing -> restart_pending -> completed
The check-in starts at the first syncDevice received after the group assignment, or
on its own after CHECKIN_FALLBACK_SECONDS. States are computed lazily on every read,
so no background thread is needed.
"""
import copy
import threading
from collections import deque
from datetime import datetime, timedelta, timezone

from config import Config
from generators.fleet import OS_TRAINS, build_fleet

STAGES = [
    (0.20, 'downloading', 'Téléchargement de la mise à jour'),
    (0.70, 'installing', 'Installation en cours'),
    (1.00, 'restart_pending', 'Redémarrage en attente'),
]
STAGE_LABELS = {
    'assigned': "Assigné, en attente de check-in de l'appareil",
    'downloading': 'Téléchargement de la mise à jour',
    'installing': 'Installation en cours',
    'restart_pending': 'Redémarrage en attente',
    'completed': 'À jour',
    'not_applicable': 'Non applicable (OS différent)',
    'already_patched': 'Déjà à jour',
}


def _now():
    return datetime.now(timezone.utc)


def _iso(dt):
    return dt.strftime('%Y-%m-%dT%H:%M:%SZ')


class Store:
    def __init__(self):
        self.lock = threading.RLock()
        self.reset()

    # ------------------------------------------------------------------ setup
    def reset(self):
        with self.lock:
            devices, entra, groups = build_fleet(Config.FILLER_DEVICES)
            self.devices = {d['id']: d for d in devices}
            self.entra = {e['id']: e for e in entra}
            self.groups = {g['id']: g for g in groups}
            self.members = {g['id']: [] for g in groups}
            self.patches = {}      # managed device id -> patch record
            self.syncs = {}        # managed device id -> datetime of last syncDevice
            self.events = deque(maxlen=300)
            self.started_at = _now()
            self._event('info', 'Simulateur', None, 'Parc Intune initialisé '
                        f'({len(self.devices)} appareils, {len(self.groups)} groupes).')

    def _event(self, level, source, device, message):
        self.events.appendleft({'ts': _iso(_now()), 'level': level, 'source': source,
                                'device': device, 'message': message})

    # --------------------------------------------------------------- lookups
    def managed_device_by_entra(self, entra_id):
        e = self.entra.get(entra_id)
        if not e:
            return None
        return next((d for d in self.devices.values() if d['azureADDeviceId'] == e['deviceId']), None)

    def entra_by_managed(self, device):
        return next((e for e in self.entra.values() if e['deviceId'] == device['azureADDeviceId']), None)

    # ----------------------------------------------------------- mutations
    def add_member(self, group_id, entra_id):
        """Returns None on success, or an error string compatible with Graph."""
        with self.lock:
            if entra_id not in self.entra:
                return 'not_found'
            if entra_id in self.members[group_id]:
                return 'exists'
            self.members[group_id].append(entra_id)
            group = self.groups[group_id]
            device = self.managed_device_by_entra(entra_id)
            name = self.entra[entra_id]['displayName']
            self._event('info', 'Cortex XSIAM', name, f"Ajout de l'appareil au groupe « {group['displayName']} ».")
            if device and group.get('_remediation'):
                self._start_patch(device, group)
            return None

    def remove_member(self, group_id, entra_id):
        with self.lock:
            if entra_id not in self.members.get(group_id, []):
                return False
            self.members[group_id].remove(entra_id)
            name = self.entra[entra_id]['displayName']
            self._event('info', 'Cortex XSIAM', name,
                        f"Retrait de l'appareil du groupe « {self.groups[group_id]['displayName']} ».")
            return True

    def _start_patch(self, device, group):
        train = OS_TRAINS[device['_train']]
        name = device['deviceName']
        if group['_os'] != device['operatingSystem']:
            stage = 'not_applicable'
            self._event('warn', 'Intune', name, f"La stratégie « {group['_policy']} » ne s'applique pas "
                        f"à un appareil {device['operatingSystem']}.")
        elif device['osVersion'] == train['patched']:
            stage = 'already_patched'
            self._event('info', 'Intune', name, 'Appareil déjà à jour, aucune action requise.')
        else:
            stage = 'assigned'
            self._event('info', 'Intune', name, f"Stratégie « {group['_policy']} » assignée : "
                        f"{train['update']}. En attente du prochain check-in.")
        self.patches[device['id']] = {
            'group_id': group['id'], 'policy': group['_policy'], 'update': train['update'],
            'from_version': device['osVersion'], 'to_version': train['patched'],
            'joined_at': _now(), 'started_at': None, 'completed_at': None, 'stage': stage,
        }

    def sync_device(self, device_id):
        with self.lock:
            device = self.devices[device_id]
            now = _now()
            self.syncs[device_id] = now
            device['deviceActionResults'] = [r for r in device['deviceActionResults']
                                             if r['actionName'] != 'syncDevice']
            device['deviceActionResults'].append({'actionName': 'syncDevice', 'actionState': 'pending',
                                                  'startDateTime': _iso(now), 'lastUpdatedDateTime': _iso(now)})
            self._event('info', 'Cortex XSIAM', device['deviceName'], 'Synchronisation forcée demandée (syncDevice).')
            patch = self.patches.get(device_id)
            if patch and patch['stage'] == 'assigned':
                patch['started_at'] = now
                self._event('info', 'Appareil', device['deviceName'],
                            'Check-in Intune reçu : la stratégie de mise à jour est appliquée.')

    # ----------------------------------------------------------- lifecycle
    def refresh(self):
        with self.lock:
            now = _now()
            for device_id, device in self.devices.items():
                for r in device['deviceActionResults']:
                    if r['actionState'] == 'pending':
                        start = datetime.strptime(r['startDateTime'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
                        if (now - start).total_seconds() >= Config.SYNC_ACTION_SECONDS:
                            r['actionState'] = 'done'
                            r['lastUpdatedDateTime'] = _iso(now)
                            device['lastSyncDateTime'] = _iso(now)

            for device_id, patch in self.patches.items():
                device = self.devices[device_id]
                if patch['stage'] in ('completed', 'not_applicable', 'already_patched'):
                    continue
                if patch['started_at'] is None:
                    waited = (now - patch['joined_at']).total_seconds()
                    if waited < Config.CHECKIN_FALLBACK_SECONDS:
                        continue
                    patch['started_at'] = patch['joined_at'] + timedelta(seconds=Config.CHECKIN_FALLBACK_SECONDS)
                    self._event('info', 'Appareil', device['deviceName'],
                                'Check-in Intune périodique : la stratégie de mise à jour est appliquée.')
                progress = (now - patch['started_at']).total_seconds() / max(Config.PATCH_DURATION_SECONDS, 1)
                new_stage = 'completed'
                for threshold, stage, _ in STAGES:
                    if progress < threshold:
                        new_stage = stage
                        break
                if new_stage != patch['stage']:
                    patch['stage'] = new_stage
                    if new_stage == 'completed':
                        self._complete(device, patch, now)
                    else:
                        self._event('info', 'Appareil', device['deviceName'],
                                    f"{STAGE_LABELS[new_stage]} : {patch['update']}.")

    def _complete(self, device, patch, now):
        patch['completed_at'] = now
        device['osVersion'] = patch['to_version']
        device['complianceState'] = 'compliant'
        device['lastSyncDateTime'] = _iso(now)
        entra = self.entra_by_managed(device)
        if entra:
            entra['operatingSystemVersion'] = patch['to_version']
            entra['isCompliant'] = True
        self._event('success', 'Intune', device['deviceName'],
                    f"Mise à jour installée ({patch['from_version']} → {patch['to_version']}). Appareil conforme.")

    def patch_progress(self, patch):
        if patch['stage'] in ('completed', 'already_patched'):
            return 100
        if patch['stage'] in ('assigned', 'not_applicable') or not patch['started_at']:
            return 0
        elapsed = (_now() - patch['started_at']).total_seconds()
        return min(99, int(100 * elapsed / max(Config.PATCH_DURATION_SECONDS, 1)))

    # ------------------------------------------------------------ console
    def snapshot(self):
        self.refresh()
        with self.lock:
            rows = []
            for d in self.devices.values():
                patch = self.patches.get(d['id'])
                groups = [self.groups[g]['displayName'] for g, m in self.members.items()
                          if any(self.managed_device_by_entra(e) is d for e in m)]
                rows.append({
                    'deviceName': d['deviceName'], 'user': d['userDisplayName'], 'upn': d['userPrincipalName'],
                    'operatingSystem': d['operatingSystem'], 'osVersion': d['osVersion'],
                    'osLabel': OS_TRAINS[d['_train']]['label'], 'complianceState': d['complianceState'],
                    'lastSyncDateTime': d['lastSyncDateTime'], 'persona': d['_persona'], 'groups': groups,
                    'patch': None if not patch else {
                        'stage': patch['stage'], 'label': STAGE_LABELS[patch['stage']],
                        'update': patch['update'], 'policy': patch['policy'],
                        'progress': self.patch_progress(patch),
                        'from_version': patch['from_version'], 'to_version': patch['to_version'],
                    },
                })
            rows.sort(key=lambda r: (not r['persona'], r['patch'] is None, r['deviceName']))
            stats = {
                'total': len(rows),
                'compliant': sum(r['complianceState'] == 'compliant' for r in rows),
                'noncompliant': sum(r['complianceState'] != 'compliant' for r in rows),
                'in_progress': sum(1 for r in rows if r['patch'] and r['patch']['stage'] in
                                   ('assigned', 'downloading', 'installing', 'restart_pending')),
                'remediated': sum(1 for r in rows if r['patch'] and r['patch']['stage'] == 'completed'),
            }
            return {'devices': rows, 'stats': stats, 'events': list(self.events)[:60],
                    'patch_duration': Config.PATCH_DURATION_SECONDS}


def public(obj):
    """Strip simulator-only keys (prefixed with '_') from a Graph object."""
    return {k: copy.deepcopy(v) for k, v in obj.items() if not k.startswith('_')}


store = Store()
