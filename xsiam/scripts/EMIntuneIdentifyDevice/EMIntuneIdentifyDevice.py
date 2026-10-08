"""
Step 1 of the demo playbook: identify the device and the vulnerability.

Reads the current Exposure Management issue (hostname, CVE, fix KBs), then finds the
device in Intune through msgraph-api-request. Outputs everything under EMIntune.*.
"""
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import re

NAME_HOST_RE = re.compile(r'\bat\s+(\S+)\s*$')
KB_RE = re.compile(r'^KB\d{6,8}$', re.IGNORECASE)


def field(issue: dict, name: str):
    return (issue.get('CustomFields') or {}).get(name) or issue.get(name)


def as_list(value) -> list:
    if value in (None, ''):
        return []
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return [v.strip() for v in value.split(',') if v.strip()]
    return value if isinstance(value, list) else [value]


def find_intune_device(device_name: str) -> dict | None:
    entries = demisto.executeCommand('msgraph-api-request', {
        'resource': '/deviceManagement/managedDevices', 'http_method': 'GET',
        'odata': f"$filter=deviceName eq '{device_name}'", 'populate_context': 'false',
    })
    for entry in entries or []:
        if is_error(entry):
            raise DemistoException(f'Intune query failed: {get_error(entry)}')
        contents = entry.get('Contents')
        if isinstance(contents, dict):
            devices = contents.get('value') or []
            return devices[0] if devices else None
    return None


def main():  # pragma: no cover
    # Start from a clean EMIntune context so the demo can be replayed on the same issue
    demisto.executeCommand('DeleteContext', {'key': 'EMIntune'})
    issue = demisto.incident() or {}
    name = issue.get('name', '')

    hostname = (demisto.args().get('hostname') or '').strip()
    if not hostname:
        m = NAME_HOST_RE.search(name)
        hostname = m.group(1) if m else ''
    short_name = hostname.split('.')[0]
    if not short_name:
        raise DemistoException(f'No hostname found in issue "{name}"')

    cve = field(issue, 'xdmvulnerabilitycveid') or (re.findall(r'CVE-\d{4}-\d{4,7}', name) or [None])[0]
    fix_kbs = list(dict.fromkeys(str(v).upper() for v in as_list(field(issue, 'xdmvulnerabilityfixversions'))
                                 if KB_RE.match(str(v))))

    device = find_intune_device(short_name)
    if not device:
        raise DemistoException(f'{hostname} is not managed by Intune: remediation goes to the asset owner.')

    outputs = {
        'Hostname': short_name,
        'CVE': cve,
        'FixKBs': fix_kbs,
        'Device': {
            'Id': device.get('id'),
            'Name': device.get('deviceName'),
            'OperatingSystem': device.get('operatingSystem'),
            'OSVersion': device.get('osVersion'),
            'ComplianceState': device.get('complianceState'),
            'User': device.get('userDisplayName'),
            'AzureADDeviceId': device.get('azureADDeviceId'),
        },
    }
    md = tableToMarkdown('Poste et vulnérabilité à remédier', {
        'Poste': device.get('deviceName'),
        'Utilisateur': device.get('userDisplayName'),
        'Système': f"{device.get('operatingSystem')} {device.get('osVersion')}",
        'Conformité Intune': device.get('complianceState'),
        'Vulnérabilité': cve,
        'Correctif(s) Microsoft': ', '.join(fix_kbs) or 'mise à jour de l\'OS',
    }, headers=['Poste', 'Utilisateur', 'Système', 'Conformité Intune', 'Vulnérabilité', 'Correctif(s) Microsoft'])
    return_results(CommandResults(outputs_prefix='EMIntune', outputs=outputs, readable_output=md))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
