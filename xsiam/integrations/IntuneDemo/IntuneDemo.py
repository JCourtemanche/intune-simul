"""
Intune (Demo) - drop-in replacement of the "Microsoft Graph API" integration for demos.

Exposes the SAME command as the official integration (msgraph-api-request, same arguments,
same "MicrosoftGraph" context output) but authenticates against a configurable endpoint,
so it can target the Intune simulator. A playbook built on this integration runs unchanged
on the official Microsoft Graph API integration once a real Entra ID app is available.
"""
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import time
from typing import Any

TOKEN_SAFETY_MARGIN = 60


class Client(BaseClient):
    def __init__(self, base_url: str, tenant_id: str, app_id: str, app_secret: str, verify: bool, proxy: bool):
        super().__init__(base_url=base_url.rstrip('/'), verify=verify, proxy=proxy,
                         ok_codes=(200, 201, 202, 204))
        self.tenant_id = tenant_id
        self.app_id = app_id
        self.app_secret = app_secret

    def get_access_token(self, force: bool = False) -> str:
        ctx = get_integration_context() or {}
        if not force and ctx.get('access_token') and ctx.get('valid_until', 0) > time.time() + TOKEN_SAFETY_MARGIN \
                and ctx.get('app_id') == self.app_id:
            return ctx['access_token']
        res = self._http_request(
            'POST', url_suffix=f'/{self.tenant_id}/oauth2/v2.0/token',
            data={'grant_type': 'client_credentials', 'client_id': self.app_id, 'client_secret': self.app_secret,
                  'scope': 'https://graph.microsoft.com/.default'},
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
        )
        token = res.get('access_token')
        if not token:
            raise DemistoException(f'Token endpoint did not return an access token: {res}')
        set_integration_context({'access_token': token, 'app_id': self.app_id,
                                 'valid_until': time.time() + int(res.get('expires_in', 3599))})
        return token

    def generic_request(self, resource: str, http_method: str = 'GET', api_version: str = 'v1.0',
                        odata: str | None = None, request_body: dict | None = None,
                        headers: dict | None = None):
        # Same URL construction as the official integration
        url_suffix = urljoin(api_version, resource)
        if odata:
            url_suffix += f'?{odata}'
        req_headers = {'Authorization': f'Bearer {self.get_access_token()}',
                       'Accept': 'application/json', 'Content-Type': 'application/json'}
        if headers:
            req_headers.update(headers)
        res = self._http_request(http_method, url_suffix=url_suffix, json_data=request_body,
                                 headers=req_headers, resp_type='response')
        return res.json() if res.content else None


def get_response_outputs(response: dict) -> dict | list:
    if 'value' in response:
        return response['value']
    res = dict(response)
    res.pop('@odata.context', None)
    return res


def generic_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Mirror of the official msgraph-api-request command."""
    request_body = args.get('request_body')
    if request_body and isinstance(request_body, str):
        try:
            request_body = json.loads(request_body)
        except json.decoder.JSONDecodeError as e:
            raise ValueError(f'Invalid request body - {e!s}')
    headers = args.get('headers')

    response = client.generic_request(
        resource=args.get('resource', ''),
        http_method=args.get('http_method', 'GET'),
        api_version=args.get('api_version', 'v1.0'),
        odata=args.get('odata', ''),
        request_body=request_body,
        headers=dict(sub.split(':', 1) for sub in headers.split(',')) if headers else None,
    )

    if not response:
        return CommandResults(readable_output='The API query ran successfully and returned no content.')

    results: dict[str, Any] = {'raw_response': response}
    if argToBoolean(args.get('populate_context', 'true')):
        outputs = get_response_outputs(response)
        results['outputs'] = outputs
        results['outputs_prefix'] = 'MicrosoftGraph'
        results['readable_output'] = tableToMarkdown('Microsoft Graph API response', outputs, removeNull=True)
    return CommandResults(**results)


def main() -> None:  # pragma: no cover
    params = demisto.params()
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            base_url=params.get('url', ''),
            tenant_id=params.get('tenant_id', ''),
            app_id=params.get('app_id', ''),
            app_secret=(params.get('credentials') or {}).get('password', ''),
            verify=not argToBoolean(params.get('insecure', False)),
            proxy=argToBoolean(params.get('proxy', False)),
        )
        if command == 'test-module':
            client.get_access_token(force=True)
            return_results('ok')
        elif command == 'msgraph-api-test':
            client.get_access_token(force=True)
            return_results(CommandResults(readable_output='```✅ Success!```'))
        elif command == 'msgraph-api-request':
            return_results(generic_command(client, demisto.args()))
        else:
            raise NotImplementedError(f'Command {command} is not implemented')
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{e!s}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
