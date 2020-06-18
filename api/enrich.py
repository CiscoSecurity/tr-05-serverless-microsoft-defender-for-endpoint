import uuid
from functools import partial
from flask import Blueprint, current_app, g

from api.schemas import ObservableSchema
from api.utils import (get_json, get_jwt, jsonify_data, jsonify_errors)
from api.errors import CTRBadRequestError
from api.client import Client

enrich_api = Blueprint('enrich', __name__)


get_observables = partial(get_json, schema=ObservableSchema(many=True))


severity = {
    # 'None',
    'Informational': 'Info',
    'Low': 'Low',
    'Medium': 'Medium',
    'High': 'High',
    'UnSpecified': 'Unknown'
}


def format_docs(docs):
    return {'count': len(docs), 'docs': docs}


def group_observables(relay_input):
    # Leave only unique observables

    result = []
    for observable in relay_input:
        o_value = observable['value']
        o_type = observable['type'].lower()

        # Get only supported types.
        if o_type in current_app.config['MD_ATP_OBSERVABLE_TYPES']:
            obj = {'type': o_type, 'value': o_value}
            if obj in result:
                continue
            result.append(obj)

    return result


def get_relation(origin, relation, source, related):
    return {
        'origin': origin,
        'relation': relation,
        'source': source,
        'related': related
    }


def get_sighting(client, observable_type, observable_value,
                 data, count, entity):
    relations = []
    targets = []

    if data['computerDnsName']:
        url = client.format_url('machines', data['machineId'])
        res = client.call_api(url)
        observables = [
            {
                'type': 'hostname',
                'value': data['computerDnsName']
            },
            {
                'type': 'ip',
                'value': res['lastIpAddress']
            }
        ]
        if data['relatedUser'] and data['relatedUser'].get('userName'):
            observables.append(
                {
                    'type': 'user',
                    'value': data['relatedUser']['userName']
                }
            )

        targets.append(
            {
                'type': 'endpoint',
                'os': res['osPlatform'],
                'observables': observables,
                'observed_time': {
                    'start_time': data['firstEventTime']
                }
            }
        )

    for evidence in data.get('evidence', []):

        def _related_sha1(value):
            return {'value': value, 'type': 'sha1'}

        def _related_sha256(value):
            return {'value': value, 'type': 'sha256'}

        if evidence.get('parentProcessId'):
            for e in data['evidence']:
                if e['processId'] == evidence['parentProcessId']:
                    relations.append(
                        get_relation(
                            data['detectionSource'],
                            'Injected_Into',
                            {'value': evidence['fileName'],
                             'type': 'file_name'},
                            {'value': e['fileName'], 'type': 'file_name'}
                        )
                    )

        if evidence.get('fileName'):
            if evidence.get('sha1'):
                relations.append(
                    get_relation(
                        data['detectionSource'],
                        'File_Name_Of',
                        {'value': evidence['fileName'], 'type': 'file_name'},
                        _related_sha1(evidence['sha1'])
                    )
                )

            if evidence.get('sha256'):
                relations.append(
                    get_relation(
                        data['detectionSource'],
                        'File_Name_Of',
                        {'value': evidence['fileName'], 'type': 'file_name'},
                        _related_sha256(evidence['sha256'])
                    )
                )

        if evidence.get('filePath'):
            if evidence.get('sha1'):
                relations.append(
                    get_relation(
                        data['detectionSource'],
                        'File_Path_Of',
                        {'value': evidence['filePath'], 'type': 'file_path'},
                        _related_sha1(evidence['sha1'])
                    )
                )

            if evidence.get('sha256'):
                relations.append(
                    get_relation(
                        data['detectionSource'],
                        'File_Path_Of',
                        {'value': evidence['filePath'], 'type': 'file_path'},
                        _related_sha256(evidence['sha256'])
                    )
                )

    return {
        'id': f'transient:{uuid.uuid4()}',
        'type': 'sighting',
        'count': count,
        'internal': True,
        'confidence': 'High',
        'source': 'Microsoft Defender ATP',
        'source_uri': f'https://securitycenter.windows.com/'
                      f'{entity}/{observable_value}/alerts',
        'observables': [
            {
                'value': observable_value,
                'type': observable_type
            }
        ],
        'schema_version': current_app.config['CTIM_SCHEMA_VERSION'],
        'sensor': 'endpoint',  # detectionSource
        'observed_time': {'start_time': data['firstEventTime']},
        'title': data['title'],
        'description': data['description'],
        'severity': severity[data['severity']] or 'None',
        'timestamp': data['lastUpdateTime'],
        'targets': targets,
        'relations': relations
    }


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

        if observable['type'] == 'sha256':
            entity = 'files'
            url = client.format_url(entity, observable['value'])
            response = client.call_api(url)
            if response is not None:
                url = client.format_url(entity, response['sha1'], '/alerts')
                response = client.call_api(url)

        elif observable['type'] == 'sha1':
            entity = 'files'
            url = client.format_url(entity, observable['value'], '/alerts')
            response = client.call_api(url)

        elif observable['type'] == 'domain':
            entity = 'urls'
            url = client.format_url('domains', observable['value'], '/alerts')
            response = client.call_api(url)

        elif observable['type'] == 'ip':
            entity = 'ips'
            url = client.format_url(entity, observable['value'], '/alerts')
            response = client.call_api(url)

        else:
            raise CTRBadRequestError(
                f"'{observable['type']}' type is not supported.")

        if not response or not response.get('value'):
            continue
        values = response['value']

        values.sort(key=lambda x: x['alertCreationTime'], reverse=True)

        count = len(values)

        if count >= current_app.config['CTR_ENTITIES_LIMIT']:
            values = values[:current_app.config['CTR_ENTITIES_LIMIT']]

        for value in values:
            sighting = get_sighting(client,
                                    observable['type'],
                                    observable['value'],
                                    value,
                                    count,
                                    entity)
            g.sightings.append(sighting)

    client.close_session()

    if g.sightings:
        data['sightings'] = format_docs(g.sightings)

    return jsonify_data(data)


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    # Not supported or implemented
    return jsonify_data([])
