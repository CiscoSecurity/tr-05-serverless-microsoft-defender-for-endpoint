import json
from os import cpu_count
from functools import partial
from flask import Blueprint, current_app, g
from concurrent.futures import ThreadPoolExecutor

from api.schemas import ObservableSchema
from api.utils import (get_json, get_jwt, jsonify_data, jsonify_errors,
                       group_observables, format_docs)
from api.errors import CTRBadRequestError
from api.client import Client
from api.mapping import Mapping

enrich_api = Blueprint('enrich', __name__)


get_observables = partial(get_json, schema=ObservableSchema(many=True))


def get_alert(client, observable):
    if observable['type'] == 'sha256':
        url = client.format_url('files', observable['value'])
        response = client.call_api(url)[0]
        if response is not None:
            url = client.format_url('files', response['sha1'], '/alerts')
            response = client.call_api(url)[0]

    elif observable['type'] == 'sha1':
        url = client.format_url('files', observable['value'], '/alerts')
        response = client.call_api(url)[0]

    elif observable['type'] == 'domain':
        url = client.format_url('domains', observable['value'], '/alerts')
        response = client.call_api(url)[0]

    elif observable['type'] in ('ip', 'ipv6'):
        url = client.format_url('ips', observable['value'], '/alerts')
        response = client.call_api(url)[0]

    else:
        raise CTRBadRequestError(
            f"'{observable['type']}' type is not supported.")
    return response


def call_advanced_hunting(client, o_value, o_type, limit):
    name_fields = {
        'sha1': 'SHA1',
        'sha256': 'SHA256',
        'domain': 'RemoteUrl',
        'ip': 'RemoteIP',
        'ipv6': 'RemoteIP'
    }

    if o_type in ('sha1', 'sha256'):
        query = "DeviceFileEvents " \
                f"| where {name_fields[o_type]} == '{o_value}' " \
                "| join kind=leftouter (DeviceNetworkInfo " \
                "| summarize (LastTimestamp)=arg_max(Timestamp, ReportId) " \
                "by DeviceId, NetworkAdapterType, MacAddress, " \
                f"DeviceName, IPAddresses) on DeviceId | limit {limit}"
    else:
        query = "DeviceNetworkEvents " \
                f"| where {name_fields[o_type]} == '{o_value}' " \
                "| join kind=leftouter (DeviceNetworkInfo " \
                "| summarize (LastTimestamp)=arg_max(Timestamp, ReportId) " \
                "by DeviceId, NetworkAdapterType, MacAddress, " \
                f"DeviceName, IPAddresses) on DeviceId | limit {limit}"

    query = json.dumps({'Query': query}).encode('utf-8')
    result, error = client.call_api(
        current_app.config['ADVANCED_HUNTING_URL'],
        'POST', data=query)

    if error is not None:
        CTRBadRequestError(error)

    return result['Results']


@enrich_api.route('/deliberate/observables', methods=['POST'])
def deliberate_observables():
    _ = get_jwt()
    _ = get_observables()
    return jsonify_data({})


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    observables, error = get_observables()
    if error:
        return jsonify_errors(error)

    observables = group_observables(observables)

    if not observables:
        return jsonify_data({})

    data = {}
    g.sightings = []

    credentials = get_jwt()
    client = Client(credentials)
    for observable in observables:
        client.open_session()

        response = get_alert(client, observable)

        if not response or not response.get('value'):
            alerts = []
        else:
            alerts = response['value']
            alerts.sort(key=lambda x: x['alertCreationTime'], reverse=True)

        count = len(alerts)

        if count >= current_app.config['CTR_ENTITIES_LIMIT']:
            alerts = alerts[:current_app.config['CTR_ENTITIES_LIMIT']]
            events = []
        else:
            events = call_advanced_hunting(
                client,
                observable['value'], observable['type'],
                current_app.config['CTR_ENTITIES_LIMIT'] - count)
            count = count + len(events)

        mapping = Mapping(client, observable, count)

        if alerts:
            with ThreadPoolExecutor(
                    max_workers=min(
                        len(alerts),
                        cpu_count() or 1
                    ) * 5) as executor:
                alerts = executor.map(mapping.build_sighting_from_alert,
                                      alerts)

            [g.sightings.append(alert) for alert in alerts if alert]

        if events:
            with ThreadPoolExecutor(
                    max_workers=min(
                        len(events),
                        cpu_count() or 1
                    ) * 5) as executor:
                events = executor.map(mapping.build_sighting_from_ah, events)

            [g.sightings.append(event) for event in events if event]

    client.close_session()

    if g.sightings:
        data['sightings'] = format_docs(g.sightings)

    return jsonify_data(data)


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    observables, error = get_observables()

    if error:
        return jsonify_errors(error)

    data = []

    for observable in observables:
        o_type = observable['type']
        o_value = observable['value']

        if o_type in ('sha1', 'sha256'):
            entity = 'files'
        elif o_type in ('ip', 'ipv6'):
            entity = 'ips'
        else:
            entity = 'urls'

        title = 'Search for this {o_type}'.format(
            o_type=current_app.config["MD_ATP_OBSERVABLE_TYPES"][o_type]
        )
        description = 'Lookup this {o_type} on Microsoft Defender ATP'.format(
            o_type=current_app.config['MD_ATP_OBSERVABLE_TYPES'][o_type]
        )
        url = '{host}/{entity}/{o_value}'.format(
            host=current_app.config['SECURITY_CENTER_URL'],
            entity=entity,
            o_value=o_value
        )

        data.append(
            {
                'id': f'ref-mdatp-search-{o_type}-{o_value}',
                'title': title,
                'description': description,
                'url': url,
                'categories': ['Search', 'Microsoft Defender ATP']
            }
        )

    return jsonify_data(data)
