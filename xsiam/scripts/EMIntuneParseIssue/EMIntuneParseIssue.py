"""
Reads the current Exposure Management vulnerability issue and exposes what the Intune
remediation playbook needs under EMIntune.*: hostname, CVE, fix KBs.

The hostname comes from the asset (core-get-asset-details output, passed as `hostname`)
and falls back to the issue name ("CVE-XXXX-YYYY vulnerability at <HOST>").
"""
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import re

NAME_HOST_RE = re.compile(r'\bat\s+(\S+)\s*$')
KB_RE = re.compile(r'^KB\d{6,8}$', re.IGNORECASE)


def field(issue: dict, *names: str):
    custom = issue.get('CustomFields') or {}
    for name in names:
        for source in (custom, issue):
            value = source.get(name)
            if value not in (None, '', [], {}):
                return value
    return None


def as_list(value) -> list:
    if value in (None, ''):
        return []
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, list) else [parsed]
        except ValueError:
            return [v.strip() for v in value.split(',') if v.strip()]
    return list(value) if isinstance(value, list | tuple) else [value]


def main():  # pragma: no cover
    args = demisto.args()
    issue = demisto.incident() or {}
    name = issue.get('name', '')

    hostname = (args.get('hostname') or '').strip()
    if isinstance(args.get('hostname'), list):
        hostname = next((h for h in args['hostname'] if h), '')
    if not hostname:
        m = NAME_HOST_RE.search(name)
        hostname = m.group(1) if m else ''

    cve = field(issue, 'xdmvulnerabilitycveid', 'cveid') or (re.search(r'CVE-\d{4}-\d{4,7}', name) or [None])[0]
    fix_versions = [str(v) for v in as_list(field(issue, 'xdmvulnerabilityfixversions'))]
    fix_kbs = list(dict.fromkeys(v.upper() for v in fix_versions if KB_RE.match(v)))
    asset_ids = as_list(field(issue, 'asset_ids', 'assetids'))

    outputs = {
        'IssueId': issue.get('id'),
        'IssueName': name,
        'Hostname': hostname,
        'ShortName': hostname.split('.')[0] if hostname else '',
        'AssetId': asset_ids[0] if asset_ids else None,
        'CVE': cve,
        'CVSS': field(issue, 'xdmvulnerabilitycvssscore'),
        'Severity': field(issue, 'xdmvulnerabilityseverity'),
        'FixKBs': fix_kbs,
        'FixVersions': fix_versions[:15],
    }

    md = tableToMarkdown('Vulnérabilité à remédier', {
        'Issue': name, 'Asset': hostname or 'introuvable', 'CVE': cve, 'CVSS': outputs['CVSS'],
        'Correctif(s) Microsoft': ', '.join(fix_kbs) or 'non applicable',
    }, headers=['Issue', 'Asset', 'CVE', 'CVSS', 'Correctif(s) Microsoft'])
    return_results(CommandResults(outputs_prefix='EMIntune', outputs=outputs, readable_output=md))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
