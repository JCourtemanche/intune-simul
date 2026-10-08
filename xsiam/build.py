"""
Builds importable XSIAM content into xsiam/dist/:
  - integration-IntuneDemo.yml                  (Settings > Integrations > upload)
  - automation-EMIntuneIdentifyDevice.yml       (Scripts > import)
  - automation-EMIntuneDeployPatch.yml          (Scripts > import)
  - automation-EMIntuneWaitForPatch.yml         (Scripts > import)
  - playbook-EM_-_Intune_Patch_Remediation.yml  (Playbooks > import)

Usage: python xsiam/build.py
"""
import json
import uuid
from pathlib import Path

import yaml

ROOT = Path(__file__).parent
DIST = ROOT / 'dist'

PLAYBOOK_ID = 'EM - Intune Patch Remediation'
SCRIPTS = ('EMIntuneIdentifyDevice', 'EMIntuneDeployPatch', 'EMIntuneWaitForPatch')

# Local-dev imports that the platform injects itself (same cleanup as `demisto-sdk unify`)
DEV_IMPORTS = (
    'import demistomock as demisto',
    'from CommonServerPython import *',
    'from CommonServerUserPython import *',
)


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


def clean_code(code):
    return '\n'.join(line for line in code.splitlines() if not line.strip().startswith(DEV_IMPORTS)) + '\n'


def unify(folder, name, kind):
    meta = yaml.safe_load((folder / f'{name}.yml').read_text(encoding='utf-8'))
    code = clean_code((folder / f'{name}.py').read_text(encoding='utf-8'))
    if kind == 'integration':
        meta['script']['script'] = code
    else:
        meta['script'] = code
    return meta


# --------------------------------------------------------------------------- playbook
# Demo playbook: 5 business steps, one human decision. The Graph plumbing (group and
# Entra ID lookups, group membership, polling) lives in the scripts so the canvas stays
# readable for a non-technical audience.

def _uuid(seed):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f'em-intune-playbook/{seed}'))


def simple(v):
    return {'simple': v}


X = 450
# id: (type, name, description, script, args, next, y, extra)
TASKS = {
    '0': ('start', '', '', None, None, {'#none#': ['1']}, 50, {}),
    '1': ('regular', '1. Identifier le poste et la vulnérabilité',
          'Lit l\'issue Exposure Management (poste, CVE, correctifs) et retrouve le poste dans Intune.',
          'EMIntuneIdentifyDevice', None, {'#none#': ['2']}, 230, {}),
    '2': ('condition', '2. Valider le déploiement du correctif ?',
          'Validation humaine avant toute action sur le poste de l\'utilisateur.',
          None, None, {'Oui': ['3'], 'Non': ['99']}, 410, {}),
    '3': ('regular', '3. Déployer le correctif via Intune',
          'Ajoute le poste au groupe ciblé par la stratégie de mise à jour Intune de sa plateforme, '
          'puis force sa synchronisation.',
          'EMIntuneDeployPatch',
          {'device_id': simple('${EMIntune.Device.Id}'),
           'azure_ad_device_id': simple('${EMIntune.Device.AzureADDeviceId}'),
           'operating_system': simple('${EMIntune.Device.OperatingSystem}'),
           'windows_group': simple('${inputs.WindowsRemediationGroup}'),
           'macos_group': simple('${inputs.MacOSRemediationGroup}'),
           'ios_group': simple('${inputs.IOSRemediationGroup}')},
          {'#none#': ['4']}, 590, {}),
    '4': ('regular', '4. Suivre l\'installation sur le poste',
          'Attend qu\'Intune remonte la nouvelle version de l\'OS et un poste conforme.',
          'EMIntuneWaitForPatch',
          {'device_id': simple('${EMIntune.Device.Id}'),
           'initial_os_version': simple('${EMIntune.Device.OSVersion}'),
           'timeout_seconds': simple('${inputs.PatchTimeoutSeconds}'),
           'interval_seconds': simple('15'),
           'execution-timeout': simple('1200')},
          {'#none#': ['5']}, 770, {}),
    '5': ('regular', '5. Clôturer l\'issue', 'Clôture avec la preuve de remédiation.',
          'Builtin|||closeInvestigation',
          {'closeReason': simple('Resolved'),
           'closeNotes': simple('Remédiation Cortex XSIAM + Intune : ${EMIntune.CVE} corrigée sur '
                                '${EMIntune.Device.Name} (groupe ${EMIntune.GroupName}). Version OS '
                                '${EMIntune.Patch.InitialOSVersion} -> ${EMIntune.Patch.OSVersion}, poste conforme.')},
          {'#none#': ['99']}, 950, {}),
    '99': ('title', 'Done', '', None, None, None, 1130, {}),
}


def build_playbook():
    tasks = {}
    for tid, (ttype, name, desc, script, args, nxt, y, extra) in TASKS.items():
        task_uuid = _uuid(tid)
        inner = {'brand': '', 'id': task_uuid, 'iscommand': False, 'name': name, 'version': -1,
                 'description': desc, 'type': ttype}
        if ttype == 'start':
            inner.pop('type')
        if script:
            inner.update({'brand': script.split('|||')[0] if '|||' in script else '',
                          'iscommand': '|||' in script, 'script': script})
        t = {
            'continueonerrortype': '', 'id': tid, 'ignoreworker': False, 'isautoswitchedtoquietmode': False,
            'isoversize': False, 'note': False, 'quietmode': 0, 'separatecontext': False,
            'skipunavailable': False, 'task': inner, 'taskid': task_uuid, 'timertriggers': [], 'type': ttype,
            'view': json.dumps({'position': {'x': X, 'y': y}}, indent=2),
        }
        if nxt:
            t['nexttasks'] = nxt
        if args:
            t['scriptarguments'] = args
        tasks[tid] = t

    return {
        'contentitemexportablefields': {'contentitemfields': {}},
        'description': 'Démonstrateur Exposure Management -> Intune : identifie le poste vulnérable, demande '
                       'une validation, déclenche la mise à jour via Intune, suit son installation et clôture '
                       'l\'issue. Fonctionne avec l\'intégration Intune (Demo) ou Microsoft Graph API.',
        'id': PLAYBOOK_ID,
        'inputs': [
            {'key': 'WindowsRemediationGroup', 'value': simple('XSIAM-Remediation-Windows-Expedite'),
             'required': False, 'description': 'Groupe ciblé par la mise à jour Windows accélérée.',
             'playbookInputQuery': None},
            {'key': 'MacOSRemediationGroup', 'value': simple('XSIAM-Remediation-macOS-Update'), 'required': False,
             'description': 'Groupe ciblé par la mise à jour macOS.', 'playbookInputQuery': None},
            {'key': 'IOSRemediationGroup', 'value': simple('XSIAM-Remediation-iOS-Update'), 'required': False,
             'description': 'Groupe ciblé par la mise à jour iOS.', 'playbookInputQuery': None},
            {'key': 'PatchTimeoutSeconds', 'value': simple('600'), 'required': False,
             'description': 'Délai maximum d\'attente de l\'installation.', 'playbookInputQuery': None},
        ],
        'name': PLAYBOOK_ID,
        'outputs': [],
        'starttaskid': '0',
        'tasks': tasks,
        'version': -1,
        'view': json.dumps({'linkLabelsPosition': {},
                            'paper': {'dimensions': {'height': 1300, 'width': 900, 'x': 0, 'y': 0}}}, indent=2),
        'tests': ['No tests'],
        'fromversion': '6.10.0',
    }


def main():
    DIST.mkdir(exist_ok=True)
    for old in DIST.glob('*.yml'):
        old.unlink()
    print('Building XSIAM content:')
    dump(unify(ROOT / 'integrations' / 'IntuneDemo', 'IntuneDemo', 'integration'), DIST / 'integration-IntuneDemo.yml')
    for name in SCRIPTS:
        dump(unify(ROOT / 'scripts' / name, name, 'script'), DIST / f'automation-{name}.yml')
    dump(build_playbook(), DIST / 'playbook-EM_-_Intune_Patch_Remediation.yml')


if __name__ == '__main__':
    main()
