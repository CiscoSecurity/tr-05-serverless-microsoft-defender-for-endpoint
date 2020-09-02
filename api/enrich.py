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
        entity = 'files'
        url = client.format_url(entity, observable['value'])
        response = client.call_api(url)[0]
        if response is not None:
            url = client.format_url(entity, response['sha1'], '/alerts')
            response = client.call_api(url)[0]

    elif observable['type'] == 'sha1':
        entity = 'files'
        url = client.format_url(entity, observable['value'], '/alerts')
        response = client.call_api(url)[0]

    elif observable['type'] == 'domain':
        entity = 'urls'
        url = client.format_url('domains', observable['value'], '/alerts')
        response = client.call_api(url)[0]

    elif observable['type'] == 'ip':
        entity = 'ips'
        url = client.format_url(entity, observable['value'], '/alerts')
        response = client.call_api(url)[0]

    else:
        raise CTRBadRequestError(
            f"'{observable['type']}' type is not supported.")
    return response, entity


def call_advanced_hunting(client, o_value, o_type, limit):

    queries = {
        'sha1': "DeviceFileEvents "
                "| where SHA1 == '{o_value}' "
                "| join kind=leftouter (DeviceNetworkInfo "
                "| summarize (LastTimestamp)=arg_max(Timestamp, ReportId) "
                "by DeviceId, NetworkAdapterType, MacAddress, "
                "DeviceName, IPAddresses) on DeviceId"
                "| limit {limit}",
        'sha256': "DeviceFileEvents "
                  "| where SHA256 == '{o_value}' "
                  "| join kind=leftouter (DeviceNetworkInfo "
                  "| summarize (LastTimestamp)=arg_max(Timestamp, ReportId) "
                  "by DeviceId, NetworkAdapterType, MacAddress, "
                  "DeviceName, IPAddresses) on DeviceId"
                  "| limit {limit}",
        'md5': "DeviceFileEvents "
               "| where MD5 == '{o_value}' "
               "| join kind=leftouter (DeviceNetworkInfo "
               "| summarize (LastTimestamp)=arg_max(Timestamp, ReportId) "
               "by DeviceId, NetworkAdapterType, MacAddress, "
               "DeviceName, IPAddresses) on DeviceId"
               "| limit {limit}",
        'ip': "DeviceNetworkEvents "
              "| where RemoteIP == '{o_value}' "
              "| join kind=leftouter (DeviceNetworkInfo "
              "| summarize (LastTimestamp)=arg_max(Timestamp, ReportId) "
              "by DeviceId, NetworkAdapterType, MacAddress, "
              "DeviceName, IPAddresses) on DeviceId"
              "| limit {limit}",
        'domain': "DeviceNetworkEvents "
                  "| where RemoteUrl == '{o_value}' "
                  "| join kind=leftouter (DeviceNetworkInfo "
                  "| summarize (LastTimestamp)=arg_max(Timestamp, ReportId) "
                  "by DeviceId, NetworkAdapterType, MacAddress, "
                  "DeviceName, IPAddresses) on DeviceId"
                  "| limit {limit}"
    }
    query = queries[o_type].format(o_value=o_value, limit=limit)
    query = json.dumps({'Query': query}).encode('utf-8')
    result, error = client.call_api(
        current_app.config['ADVANCED_HUNTING_URL'],
        'POST', query)

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

        response, entity = get_alert(client, observable)

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

        mapping = Mapping(client, observable, count, entity)

        if alerts:
            with ThreadPoolExecutor(
                    max_workers=min(
                        len(alerts),
                        cpu_count() or 1
                    ) * 5) as executor:
                alerts = executor.map(mapping.build_sighting_from_alert, alerts)

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

    # TODO: Remove logger
    # print('### Output for /observe/observables', ':', data)
    # current_app.logger.error('### Output for /observe/observables')
    # current_app.logger.error(data)
    # current_app.logger.error('#########')

    return jsonify_data(data)


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    # Not supported or implemented
    return jsonify_data([])
