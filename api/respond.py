import json
from functools import partial

from flask import Blueprint, current_app, g, jsonify

from api.schemas import ObservableSchema, ActionFormParamsSchema
from api.utils import (get_json, jsonify_data, jsonify_errors, get_jwt,
                       group_observables)
from api.client import Client
from api.errors import CTRBadRequestError

respond_api = Blueprint('respond', __name__)


get_observables = partial(get_json, schema=ObservableSchema(many=True))
get_action_form_params = partial(get_json, schema=ActionFormParamsSchema())


SELECTIVE_ISOLATION = 'SelectiveIsolation'
FULL_ISOLATION = 'FullIsolation'
COLLECT_INVESTIGATION = 'CollectInvestigationPackage'
RESTRICT_CODE_EXECUTION = 'RestrictCodeExecution'
INITIATE_INVESTIGATION = 'InitiateInvestigation'
RUN_ANTI_VIRUS_SCAN = 'RunAntiVirusScan'
RUN_ANTI_VIRUS_SCAN_QUICK = 'RunAntiVirusScanQuick'
RUN_ANTI_VIRUS_SCAN_FULL = 'RunAntiVirusScanFull'
UNISOLATE = 'Unisolate'
UNRESTRICT_CODE_EXECUTION = 'UnrestrictCodeExecution'

TR_SUPPORTED_ACTIONS = {
    FULL_ISOLATION: 'Isolate Device: Full',
    SELECTIVE_ISOLATION: 'Isolate Device: Selective',
    RUN_ANTI_VIRUS_SCAN_QUICK: 'Run antivirus scan: Quick',
    RUN_ANTI_VIRUS_SCAN_FULL: 'Run antivirus scan: Full',
    COLLECT_INVESTIGATION: 'Collect investigation package',
    RESTRICT_CODE_EXECUTION: 'Restrict app execution',
    INITIATE_INVESTIGATION: 'Initiate automated investigation',
    UNISOLATE: 'Release from isolation',
    UNRESTRICT_CODE_EXECUTION: 'Remove app restrictions'
}

_TR_SUPPORTED_ACTIONS = {
    'Isolate Device: Full': FULL_ISOLATION,
    'Isolate Device: Selective': SELECTIVE_ISOLATION,
    'Run antivirus scan: Quick': RUN_ANTI_VIRUS_SCAN_QUICK,
    'Run antivirus scan: Full': RUN_ANTI_VIRUS_SCAN_FULL,
    'Collect investigation package': COLLECT_INVESTIGATION,
    'Restrict app execution': RESTRICT_CODE_EXECUTION,
    'Initiate automated investigation': INITIATE_INVESTIGATION,
    'Release from isolation': UNISOLATE,
    'Remove app restrictions': UNRESTRICT_CODE_EXECUTION
}


def get_supported_actions(client, machine_id):
    url = f"{current_app.config['BASE_URL']}" \
          f"/machines/{machine_id}/availableMachineActions"

    response, error = client.call_api(url)
    if error:
        raise CTRBadRequestError()

    actions = []
    for item in response.get('value', []):
        if item['isAvailable']:
            if item['action'] == RUN_ANTI_VIRUS_SCAN:
                actions.append(
                    TR_SUPPORTED_ACTIONS[RUN_ANTI_VIRUS_SCAN_QUICK]
                )
                actions.append(
                    TR_SUPPORTED_ACTIONS[RUN_ANTI_VIRUS_SCAN_FULL]
                )

            else:
                if TR_SUPPORTED_ACTIONS.get(item['action']):
                    actions.append(
                        TR_SUPPORTED_ACTIONS[item['action']]
                    )
    actions.sort()

    return actions


def get_reverse_actions(client, machine_id, actions):
    url = f"{current_app.config['BASE_URL']}" \
          f"/machines/{machine_id}/machineactions?"

    if TR_SUPPORTED_ACTIONS[FULL_ISOLATION] in actions \
            or TR_SUPPORTED_ACTIONS[SELECTIVE_ISOLATION] in actions:
        filter_by_isolate = "$filter=type in ('Unisolate', 'Isolate') " \
                            "and status eq 'Succeeded'&$top=1"
        response, error = client.call_api(url + filter_by_isolate)
        if error:
            raise CTRBadRequestError()

        if response.get('value', []) and \
                response['value'][0]['type'] == 'Isolate':
            actions.remove(
                TR_SUPPORTED_ACTIONS[FULL_ISOLATION]
            )
            actions.remove(
                TR_SUPPORTED_ACTIONS[SELECTIVE_ISOLATION]
            )
            actions.append(
                TR_SUPPORTED_ACTIONS[UNISOLATE]
            )

    if TR_SUPPORTED_ACTIONS[RESTRICT_CODE_EXECUTION] in actions:
        filter_by_restrict = "$filter=type in (" \
                             "'UnrestrictCodeExecution', " \
                             "'RestrictCodeExecution'" \
                             ") and status eq 'Succeeded'&$top=1"
        response, error = client.call_api(url + filter_by_restrict)
        if error:
            raise CTRBadRequestError()
        if response.get('value', []) and \
                response['value'][0]['type'] == 'RestrictCodeExecution':
            actions.remove(
                TR_SUPPORTED_ACTIONS[RESTRICT_CODE_EXECUTION]
            )
            actions.append(
                TR_SUPPORTED_ACTIONS[UNRESTRICT_CODE_EXECUTION]
            )

    return actions


@respond_api.route('/respond/observables', methods=['POST'])
def respond_observables():
    observables, error = get_observables()
    if error:
        return jsonify_errors(error)

    observables = group_observables(observables)

    if not observables:
        return jsonify_data([])

    g.actions = []

    credentials = get_jwt()
    client = Client(credentials)
    client.open_session()

    for observable in observables:

        query_params = {'observable_type': observable['type'],
                        'observable_value': observable['value']}

        if observable['type'] == 'ms_machine_id':
        # if observable['type'] == 'device':

            _actions = get_supported_actions(client, observable['value'])
            _actions = get_reverse_actions(client,
                                           observable['value'],
                                           _actions)

            actions = []
            for item in _actions:
                action = {}
                action['id'] = \
                    f'microsoft-defender-atp-{_TR_SUPPORTED_ACTIONS[item]}'

                action['title'] = item
                action['description'] = item

                action['categories'] = [
                    'Microsoft Defender ATP',
                    'Machine Actions'
                ]
                action['query-params'] = query_params

                actions.append(action)

        else:

            params = "$filter=indicatorValue+eq+'{value}'&$top=1".format(
                value=observable['value']).encode('utf-8')

            response, error = client.call_api(
                current_app.config['INDICATOR_URL'],
                params=params
            )

            if response and response.get('value'):
                obj = response['value'][0]
                human_action = 'Alert and Block' \
                    if obj['action'] == 'AlertAndBlock' else obj['action']
                query_params['indicator_id'] = obj['id']
                actions = [
                    {
                        'id': 'microsoft-defender-atp-remove-indicator',
                        'title': 'Remove indicator: {action} - {title}'.format(
                            action=human_action,
                            title=obj['title']
                        ),
                        'description': f'Remove indicator with {human_action} '
                                       f'action for {observable["value"]}',
                        'categories': [
                            'Microsoft Defender ATP',
                            'Remove Indicator'
                        ],
                        'query-params': query_params
                    },
                ]
            else:
                actions = [
                    {
                        'id': 'microsoft-defender-atp-add-indicator-alert',
                        'title': 'Add indicator: Alert',
                        'description': f'Add indicator with Alert action '
                                       f'for {observable["value"]}',
                        'categories': [
                            'Microsoft Defender ATP',
                            'Add Indicator'
                        ],
                        'query-params': query_params
                    },
                    {
                        'id': 'microsoft-defender-atp-'
                              'add-indicator-alert-and-block',
                        'title': 'Add indicator: Alert and Block',
                        'description': f'Add indicator with '
                                       f'Alert and Block action'
                                       f' for {observable["value"]}',
                        'categories': [
                            'Microsoft Defender ATP',
                            'Add Indicator'
                        ],
                        'query-params': query_params
                    },
                    {
                        'id': 'microsoft-defender-atp-add-indicator-allowed',
                        'title': 'Add indicator: Allow',
                        'description': f'Add indicator with Allow action '
                                       f'for {observable["value"]}',
                        'categories': [
                            'Microsoft Defender ATP',
                            'Add Indicator'
                        ],
                        'query-params': query_params
                    }
                ]
        g.actions.extend(actions)

    client.close_session()

    return jsonify_data(g.actions)


@respond_api.route('/respond/trigger', methods=['POST'])
def respond_trigger():
    mapping_by_type = {
        'sha1': 'FileSha1',
        'sha256': 'FileSha256',
        'ip': 'IpAddress',
        'ipv6': 'IpAddress',
        'domain': 'DomainName'
    }
    data, error = get_action_form_params()

    if error:
        return jsonify_errors(error)

    title = 'From SecureX Threat Response'
    description = 'This indicator was added via SecureX Threat Response ' \
                  'by the UI or API response actions'

    if data['observable_type'] == 'ms_machine_id':
    # if data['observable_type'] == 'device':
        comment = 'Performed via SecureX Threat Response'

        actions = {
            'microsoft-defender-atp-FullIsolation': {
                'url': '{base_url}/machines/{machine_id}/isolate'.format(
                    base_url=current_app.config['BASE_URL'],
                    machine_id=data['observable_value']),
                'method': 'POST',
                'data': {'Comment': comment, 'IsolationType': 'Full'}
            },
            'microsoft-defender-atp-SelectiveIsolation': {
                'url': '{base_url}/machines/{machine_id}/isolate'.format(
                    base_url=current_app.config['BASE_URL'],
                    machine_id=data['observable_value']),
                'method': 'POST',
                'data': {'Comment': comment, 'IsolationType': 'Selective'}
            },
            'microsoft-defender-atp-Unisolate': {
                'url': '{base_url}/machines/{machine_id}/unisolate'.format(
                    base_url=current_app.config['BASE_URL'],
                    machine_id=data['observable_value']),
                'method': 'POST',
                'data': {'Comment': comment}
            },
            'microsoft-defender-atp-RestrictCodeExecution': {
                'url': '{base_url}/machines/{machine_id}'
                       '/restrictCodeExecution'.format(
                        base_url=current_app.config['BASE_URL'],
                        machine_id=data['observable_value']),
                'method': 'POST',
                'data': {'Comment': comment}
            },
            'microsoft-defender-atp-UnrestrictCodeExecution': {
                'url': '{base_url}/machines/{machine_id}'
                       '/unrestrictCodeExecution'.format(
                        base_url=current_app.config['BASE_URL'],
                        machine_id=data['observable_value']),
                'method': 'POST',
                'data': {'Comment': comment}
            },
            'microsoft-defender-atp-RunAntiVirusScanQuick': {
                'url': '{base_url}/machines/{machine_id}'
                       '/runAntiVirusScan'.format(
                        base_url=current_app.config['BASE_URL'],
                        machine_id=data['observable_value']),
                'method': 'POST',
                'data': {'Comment': comment, 'ScanType': 'Quick'}
            },
            'microsoft-defender-atp-RunAntiVirusScanFull': {
                'url': '{base_url}/machines/{machine_id}'
                       '/runAntiVirusScan'.format(
                        base_url=current_app.config['BASE_URL'],
                        machine_id=data['observable_value']),
                'method': 'POST',
                'data': {'Comment': comment, 'ScanType': 'Full'}
            },
            'microsoft-defender-atp-CollectInvestigationPackage': {
                'url': '{base_url}/machines/{machine_id}'
                       '/collectInvestigationPackage'.format(
                        base_url=current_app.config['BASE_URL'],
                        machine_id=data['observable_value']),
                'method': 'POST',
                'data': {'Comment': comment}
            },
            'microsoft-defender-atp-InitiateInvestigation': {
                'url': '{base_url}/machines/{machine_id}'
                       '/startInvestigation'.format(
                        base_url=current_app.config['BASE_URL'],
                        machine_id=data['observable_value']),
                'method': 'POST',
                'data': {'Comment': comment}
            }
        }

    else:
        actions = {
            'microsoft-defender-atp-add-indicator-alert': {
                'url': current_app.config['INDICATOR_URL'],
                'method': 'POST',
                'data': {
                    'indicatorValue': data['observable_value'],
                    'indicatorType': mapping_by_type[data['observable_type']],
                    'action': 'Alert',
                    'title': title,
                    'description': description,
                    'severity': 'High'
                }
            },
            'microsoft-defender-atp-add-indicator-alert-and-block': {
                'url': current_app.config['INDICATOR_URL'],
                'method': 'POST',
                'data': {
                    'indicatorValue': data['observable_value'],
                    'indicatorType': mapping_by_type[data['observable_type']],
                    'action': 'AlertAndBlock',
                    'title': title,
                    'description': description,
                    'severity': 'High'
                }
            },
            'microsoft-defender-atp-add-indicator-allowed': {
                'url': current_app.config['INDICATOR_URL'],
                'method': 'POST',
                'data': {
                    'indicatorValue': data['observable_value'],
                    'indicatorType': mapping_by_type[data['observable_type']],
                    'action': 'Allowed',
                    'title': title,
                    'description': description
                }
            },
            'microsoft-defender-atp-remove-indicator': {
                'url': current_app.config['INDICATOR_URL'] + '/' + str(
                    data.get('indicator_id', '')),
                'method': 'DELETE',
                'data': {}
            }
        }

    result = {'data': {'status': 'success'}}

    item = actions.get(data['action-id'])
    if not item:
        result['data']['status'] = 'failure'
        result['errors'] = [CTRBadRequestError("Unsupported action.").json, ]
        return jsonify(result)

    if item['data']:
        action = json.dumps(item['data']).encode('utf-8')
    else:
        action = None
    credentials = get_jwt()
    client = Client(credentials)
    client.open_session()
    response, error = client.call_api(item['url'], item['method'], data=action)
    client.close_session()

    if error is not None:
        result['data']['status'] = 'failure'
        result['errors'] = [CTRBadRequestError(error).json, ]

    return jsonify(result)
