"""
Waits until Intune reports the device as patched: osVersion differs from the version
recorded before remediation AND complianceState is "compliant".

Polls GET /deviceManagement/managedDevices/<id> through msgraph-api-request, so it works
with both the official Microsoft Graph API integration and the Intune (Demo) one.
"""
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import time


def get_device(device_id: str, using: str | None) -> dict:
    cmd_args = {'resource': f'/deviceManagement/managedDevices/{device_id}', 'http_method': 'GET',
                'populate_context': 'false'}
    if using:
        cmd_args['using'] = using
    entries = demisto.executeCommand('msgraph-api-request', cmd_args)
    errors = []
    for entry in entries or []:
        if is_error(entry):
            errors.append(get_error(entry))
            continue
        contents = entry.get('Contents')
        if isinstance(contents, str):
            try:
                contents = json.loads(contents)
            except ValueError:
                continue
        if isinstance(contents, dict) and contents.get('id'):
            return contents
    raise DemistoException(f'Could not read the Intune device {device_id}: {"; ".join(errors) or "empty response"}')


def main():  # pragma: no cover
    args = demisto.args()
    device_id = args['device_id']
    initial = str(args.get('initial_os_version') or '')
    timeout = arg_to_number(args.get('timeout_seconds')) or 600
    interval = arg_to_number(args.get('interval_seconds')) or 20
    using = args.get('using')

    start = time.time()
    timeline = []
    last_state = None
    device: dict = {}
    while True:
        device = get_device(device_id, using)
        state = (device.get('osVersion'), device.get('complianceState'))
        if state != last_state:
            timeline.append({'Temps écoulé': f'{int(time.time() - start)} s', 'Version OS': state[0],
                             'Conformité': state[1]})
            last_state = state
        patched = state[0] and state[0] != initial and state[1] == 'compliant'
        if patched or time.time() - start + interval > timeout:
            break
        time.sleep(interval)

    status = 'Completed' if patched else 'Timeout'
    outputs = {
        'DeviceId': device_id, 'DeviceName': device.get('deviceName'), 'Status': status,
        'InitialOSVersion': initial, 'OSVersion': device.get('osVersion'),
        'ComplianceState': device.get('complianceState'), 'DurationSeconds': int(time.time() - start),
    }
    title = (f"Correctif installé sur {device.get('deviceName')} ({initial} → {device.get('osVersion')})"
             if patched else f"Correctif non confirmé sur {device.get('deviceName')} après {timeout} s")
    return_results(CommandResults(outputs_prefix='EMIntune.Patch', outputs=outputs,
                                  readable_output=tableToMarkdown(title, timeline)))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
