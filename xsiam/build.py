"""
Builds importable XSIAM content into xsiam/dist/:
  - integration-IntuneDemo.yml           (Settings > Integrations > upload)
  - automation-EMIntuneParseIssue.yml    (Scripts > import)
  - automation-EMIntuneWaitForPatch.yml  (Scripts > import)
  - playbook-EM_-_Intune_Patch_Remediation.yml (Playbooks > import)

Usage: python xsiam/build.py
"""
import json
import uuid
from pathlib import Path

import yaml

ROOT = Path(__file__).parent
DIST = ROOT / 'dist'

PLAYBOOK_ID = 'EM - Intune Patch Remediation'


class LiteralDumper(yaml.SafeDumper):
    pass


def _str_presenter(dumper, data):
    if '\n' in data:
        return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
    return dumper.represent_scalar('tag:yaml.org,2002:str', data)


LiteralDumper.add_representer(str, _str_presenter)


def dump(obj, path):
    path.write_text(yaml.dump(obj, Dumper=LiteralDumper, sort_keys=False, allow_unicode=True, width=1000),
                    encoding='utf-8')
    print(f'  {path.relative_to(ROOT.parent)}')


def unify(folder, name, kind):
    meta = yaml.safe_load((folder / f'{name}.yml').read_text(encoding='utf-8'))
    code = (folder / f'{name}.py').read_text(encoding='utf-8')
    if kind == 'integration':
        meta['script']['script'] = code
    else:
        meta['script'] = code
    return meta


# --------------------------------------------------------------------------- playbook
def _uuid(seed):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f'em-intune-playbook/{seed}'))


def simple(v):
    return {'simple': v}


def cond(label, operator, left, right=None, right_is_context=False):
    c = {'operator': operator, 'left': {'value': simple(left), 'iscontext': True}}
    if right is not None:
        c['right'] = {'value': simple(right)}
        if right_is_context:
            c['right']['iscontext'] = True
    return {'label': label, 'condition': [[c]]}


GRAPH = '|||msgraph-api-request'

# id: (type, name, description, script, args, next, (x, y), extra)
TASKS = {
    '0': ('start', '', '', None, None, {'#none#': ['1']}, (450, 50), {}),
    '1': ('regular', 'Réinitialiser le contexte', 'Repart d\'un contexte propre (permet de rejouer la démo).',
          'DeleteContext', {'all': simple('yes')}, {'#none#': ['2']}, (450, 200), {}),
    '2': ('regular', 'Récupérer l\'asset Exposure Management', 'Lit l\'asset rattaché à l\'issue (nom, OS, tags).',
          'Cortex Core - IR|||core-get-asset-details', {'asset_id': simple('${alert.asset_ids}')},
          {'#none#': ['3']}, (450, 350), {'continueonerror': True}),
    '3': ('regular', 'Identifier le poste, la CVE et les correctifs',
          'Extrait le hostname, la CVE et les KB correctifs de l\'issue.',
          'EMIntuneParseIssue', {'hostname': simple('${Core.CoreAsset.xdm__asset__name}')},
          {'#none#': ['4']}, (450, 500), {}),
    '4': ('condition', 'Poste identifié ?', '', None, None, {'yes': ['5'], '#default#': ['90']}, (450, 650),
          {'conditions': [cond('yes', 'isNotEmpty', 'EMIntune.ShortName')]}),
    '5': ('regular', 'Préparer la requête Intune', '', 'DeleteContext', {'key': simple('MicrosoftGraph')},
          {'#none#': ['6']}, (450, 800), {}),
    '6': ('regular', 'Rechercher le poste dans Intune',
          'GET /deviceManagement/managedDevices filtré sur le nom du poste.', GRAPH,
          {'resource': simple('/deviceManagement/managedDevices'), 'http_method': simple('GET'),
           'api_version': simple('v1.0'), 'odata': simple("$filter=deviceName eq '${EMIntune.ShortName}'")},
          {'#none#': ['7']}, (450, 950), {}),
    '7': ('condition', 'Poste géré par Intune ?', 'Les serveurs ne sont pas gérés par Intune.', None, None,
          {'yes': ['8'], '#default#': ['80']}, (450, 1100),
          {'conditions': [cond('yes', 'isNotEmpty', 'MicrosoftGraph.id')]}),
    '80': ('regular', 'Noter : asset hors Intune', '', 'Print',
           {'value': simple('${EMIntune.Hostname} n\'est pas géré par Intune (serveur ou équipement hors parc '
                            'utilisateur). La remédiation de ${EMIntune.CVE} est confiée à l\'owner de l\'asset.')},
           {'#none#': ['81']}, (50, 1250), {}),
    '81': ('regular', 'Assigner la remédiation à l\'owner de l\'asset',
           'Asset hors Intune : assigner l\'issue à l\'équipe propriétaire (voir le champ Remediation Owners) '
           'ou créer un ticket, puis marquer la tâche comme terminée.',
           None, None, {'#none#': ['99']}, (50, 1400), {}),
    '8': ('regular', 'Mémoriser le poste Intune', '', 'Set',
          {'key': simple('EMIntune.Device'), 'value': simple('${MicrosoftGraph}')},
          {'#none#': ['9']}, (450, 1250), {}),
    '9': ('regular', 'Résumé avant approbation', '', 'Print',
          {'value': simple('Poste ${EMIntune.Device.deviceName} (${EMIntune.Device.operatingSystem} '
                           '${EMIntune.Device.osVersion}, conformité : ${EMIntune.Device.complianceState}), '
                           'utilisateur ${EMIntune.Device.userDisplayName}. Vulnérabilité ${EMIntune.CVE} '
                           '(CVSS ${EMIntune.CVSS}). Correctifs Microsoft : ${EMIntune.FixKBs}.')},
          {'#none#': ['10']}, (450, 1400), {}),
    '10': ('condition', 'Approuver le déploiement du correctif via Intune ?',
           'Validation humaine avant toute action sur le poste de l\'utilisateur.', None, None,
           {'Oui': ['11'], 'Non': ['85']}, (450, 1550), {}),
    '85': ('regular', 'Noter : correctif refusé', '', 'Print',
           {'value': simple('Déploiement du correctif refusé par l\'analyste pour ${EMIntune.Hostname}.')},
           {'#none#': ['99']}, (850, 1700), {}),
    '11': ('condition', 'Quelle plateforme ?', 'Choisit le groupe de remédiation Intune selon l\'OS.', None, None,
           {'Windows': ['12'], 'macOS': ['30'], 'iOS': ['31'], '#default#': ['90']}, (450, 1700),
           {'conditions': [cond('Windows', 'isEqualString', 'EMIntune.Device.operatingSystem', 'Windows'),
                           cond('macOS', 'isEqualString', 'EMIntune.Device.operatingSystem', 'macOS'),
                           cond('iOS', 'isEqualString', 'EMIntune.Device.operatingSystem', 'iOS')]}),
    '12': ('regular', 'Groupe : Windows (expedite)', '', 'Set',
           {'key': simple('EMIntune.GroupName'), 'value': simple('${inputs.WindowsRemediationGroup}')},
           {'#none#': ['13']}, (100, 1850), {}),
    '30': ('regular', 'Groupe : macOS', '', 'Set',
           {'key': simple('EMIntune.GroupName'), 'value': simple('${inputs.MacOSRemediationGroup}')},
           {'#none#': ['13']}, (450, 1850), {}),
    '31': ('regular', 'Groupe : iOS', '', 'Set',
           {'key': simple('EMIntune.GroupName'), 'value': simple('${inputs.IOSRemediationGroup}')},
           {'#none#': ['13']}, (800, 1850), {}),
    '13': ('regular', 'Préparer la requête groupe', '', 'DeleteContext', {'key': simple('MicrosoftGraph')},
           {'#none#': ['14']}, (450, 2000), {}),
    '14': ('regular', 'Rechercher le groupe de remédiation', 'GET /groups filtré sur le nom du groupe.', GRAPH,
           {'resource': simple('/groups'), 'http_method': simple('GET'), 'api_version': simple('v1.0'),
            'odata': simple("$filter=displayName eq '${EMIntune.GroupName}'")},
           {'#none#': ['15']}, (450, 2150), {}),
    '15': ('regular', 'Mémoriser le groupe', '', 'Set',
           {'key': simple('EMIntune.GroupId'), 'value': simple('${MicrosoftGraph.id}')},
           {'#none#': ['16']}, (450, 2300), {}),
    '16': ('regular', 'Préparer la requête Entra ID', '', 'DeleteContext', {'key': simple('MicrosoftGraph')},
           {'#none#': ['17']}, (450, 2450), {}),
    '17': ('regular', 'Rechercher l\'objet appareil Entra ID',
           'GET /devices filtré sur azureADDeviceId (l\'appartenance aux groupes porte sur l\'objet Entra ID).',
           GRAPH,
           {'resource': simple('/devices'), 'http_method': simple('GET'), 'api_version': simple('v1.0'),
            'odata': simple("$filter=deviceId eq '${EMIntune.Device.azureADDeviceId}'")},
           {'#none#': ['18']}, (450, 2600), {}),
    '18': ('regular', 'Mémoriser l\'objet Entra ID', '', 'Set',
           {'key': simple('EMIntune.EntraObjectId'), 'value': simple('${MicrosoftGraph.id}')},
           {'#none#': ['19']}, (450, 2750), {}),
    '19': ('regular', 'Ajouter le poste au groupe de remédiation',
           'POST /groups/{id}/members/$ref. La stratégie de mise à jour Intune ciblant ce groupe s\'applique '
           'alors au poste. Erreur ignorée si le poste est déjà membre.', GRAPH,
           {'resource': simple('/groups/${EMIntune.GroupId}/members/$ref'), 'http_method': simple('POST'),
            'api_version': simple('v1.0'),
            'request_body': simple('{"@odata.id": "https://graph.microsoft.com/v1.0/directoryObjects/'
                                   '${EMIntune.EntraObjectId}"}')},
           {'#none#': ['20']}, (450, 2900), {'continueonerror': True}),
    '20': ('regular', 'Forcer la synchronisation du poste', 'POST /deviceManagement/managedDevices/{id}/syncDevice',
           GRAPH,
           {'resource': simple('/deviceManagement/managedDevices/${EMIntune.Device.id}/syncDevice'),
            'http_method': simple('POST'), 'api_version': simple('v1.0')},
           {'#none#': ['21']}, (450, 3050), {}),
    '21': ('regular', 'Suivre l\'installation du correctif',
           'Interroge Intune jusqu\'à ce que le poste remonte une nouvelle version d\'OS et soit conforme.',
           'EMIntuneWaitForPatch',
           {'device_id': simple('${EMIntune.Device.id}'), 'initial_os_version': simple('${EMIntune.Device.osVersion}'),
            'timeout_seconds': simple('${inputs.PatchTimeoutSeconds}'), 'interval_seconds': simple('15'),
            'execution-timeout': simple('1200')},
           {'#none#': ['22']}, (450, 3200), {}),
    '22': ('condition', 'Correctif confirmé par Intune ?', '', None, None,
           {'yes': ['23'], '#default#': ['90']}, (450, 3350),
           {'conditions': [cond('yes', 'isEqualString', 'EMIntune.Patch.Status', 'Completed')]}),
    '23': ('regular', 'Clôturer l\'issue', '', 'Builtin|||closeInvestigation',
           {'closeReason': simple('Resolved'),
            'closeNotes': simple('Remédiation automatisée Cortex XSIAM + Intune : ${EMIntune.CVE} corrigée sur '
                                 '${EMIntune.Device.deviceName} via le groupe ${EMIntune.GroupName}. Version OS '
                                 '${EMIntune.Patch.InitialOSVersion} -> ${EMIntune.Patch.OSVersion}, poste conforme '
                                 '(${EMIntune.Patch.DurationSeconds} s). Confirmation finale au prochain scan de '
                                 'vulnérabilités.')},
           {'#none#': ['99']}, (450, 3500), {}),
    '90': ('regular', 'Analyst action',
           'Remédiation automatique impossible ou non confirmée (poste non identifié, plateforme non couverte, '
           'ou correctif non installé dans le délai). Vérifier le poste dans la console Intune, puis traiter '
           'l\'issue selon le processus de gestion des vulnérabilités.',
           None, None, {'#none#': ['99']}, (850, 3500), {}),
    '99': ('title', 'Done', '', None, None, None, (450, 3700), {}),
}

LINK_LABELS = {}


def build_playbook():
    tasks = {}
    for tid, (ttype, name, desc, script, args, nxt, (x, y), extra) in TASKS.items():
        task_uuid = _uuid(tid)
        inner = {'brand': '', 'id': task_uuid, 'iscommand': False, 'name': name, 'version': -1,
                 'description': desc, 'type': ttype if ttype != 'start' else 'start'}
        if script:
            brand = script.split('|||')[0] if '|||' in script else ''
            inner.update({'brand': brand, 'iscommand': '|||' in script, 'script': script})
        if ttype == 'start':
            inner.pop('type')
        t = {
            'continueonerrortype': '', 'id': tid, 'ignoreworker': False, 'isautoswitchedtoquietmode': False,
            'isoversize': False, 'note': False, 'quietmode': 0, 'separatecontext': False,
            'skipunavailable': False, 'task': inner, 'taskid': task_uuid, 'timertriggers': [], 'type': ttype,
            'view': json.dumps({'position': {'x': x, 'y': y}}, indent=2),
        }
        if nxt:
            t['nexttasks'] = nxt
        if args:
            t['scriptarguments'] = args
        if extra.get('conditions'):
            t['conditions'] = extra['conditions']
        if extra.get('continueonerror'):
            t['continueonerror'] = True
        tasks[tid] = t

    max_y = max(p[6][1] for p in TASKS.values())
    max_x = max(p[6][0] for p in TASKS.values())
    return {
        'contentitemexportablefields': {'contentitemfields': {}},
        'description': 'Exposure Management -> Intune: remédie une vulnérabilité de poste utilisateur (Windows, macOS, '
                       'iOS) en ajoutant le poste au groupe Intune ciblé par la stratégie de mise à jour, après '
                       'approbation, puis vérifie l\'installation du correctif et clôture l\'issue. Fonctionne avec '
                       'l\'intégration Intune (Demo) ou l\'intégration officielle Microsoft Graph API.',
        'id': PLAYBOOK_ID,
        'inputs': [
            {'key': 'WindowsRemediationGroup', 'value': simple('XSIAM-Remediation-Windows-Expedite'),
             'required': False, 'description': 'Groupe Entra ID ciblé par le profil Intune de mise à jour Windows '
                                               'accélérée (expedite).', 'playbookInputQuery': None},
            {'key': 'MacOSRemediationGroup', 'value': simple('XSIAM-Remediation-macOS-Update'), 'required': False,
             'description': 'Groupe Entra ID ciblé par la stratégie de mise à jour macOS.', 'playbookInputQuery': None},
            {'key': 'IOSRemediationGroup', 'value': simple('XSIAM-Remediation-iOS-Update'), 'required': False,
             'description': 'Groupe Entra ID ciblé par la stratégie de mise à jour iOS.', 'playbookInputQuery': None},
            {'key': 'PatchTimeoutSeconds', 'value': simple('600'), 'required': False,
             'description': 'Délai maximum d\'attente de l\'installation du correctif.', 'playbookInputQuery': None},
        ],
        'name': PLAYBOOK_ID,
        'outputs': [],
        'starttaskid': '0',
        'tasks': tasks,
        'version': -1,
        'view': json.dumps({'linkLabelsPosition': LINK_LABELS,
                            'paper': {'dimensions': {'height': max_y + 200, 'width': max_x + 400, 'x': 0, 'y': 0}}},
                           indent=2),
        'tests': ['No tests'],
        'fromversion': '6.10.0',
    }


def main():
    DIST.mkdir(exist_ok=True)
    print('Building XSIAM content:')
    dump(unify(ROOT / 'integrations' / 'IntuneDemo', 'IntuneDemo', 'integration'), DIST / 'integration-IntuneDemo.yml')
    for name in ('EMIntuneParseIssue', 'EMIntuneWaitForPatch'):
        dump(unify(ROOT / 'scripts' / name, name, 'script'), DIST / f'automation-{name}.yml')
    dump(build_playbook(), DIST / 'playbook-EM_-_Intune_Patch_Remediation.yml')


if __name__ == '__main__':
    main()
