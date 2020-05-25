import uuid
import requests
from functools import partial
from flask import Blueprint, current_app, g

from api.schemas import ObservableSchema
from api.utils import (get_json, get_jwt, jsonify_data,
                       jsonify_errors, call_api)
from api.errors import CTRBadRequestError

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


def get_sighting(observable_type, observable_value, data, count, entity):
    relations = []
    targets = []

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

        if evidence.get('domainName'):
            targets.append(
                {
                    'type': 'endpoint',
                    'observables': [
                        {
                            'type': 'hostname',
                            'value': evidence['domainName']
                        },
                    ],
                    'observed_time': {
                        'start_time': data['firstEventTime']
                    }
                }
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

    with requests.Session() as session:
        session.headers = {}
        for observable in observables:
            o_value = observable['value']
            o_type = observable['type']

            url = current_app.config['API_URL']

            if o_type == 'sha256':
                entity = 'files'
                get_file_url = url.format(entity=entity, value=o_value)
                response = call_api(session, get_file_url)
                url = url.format(
                    entity=entity,
                    value=response['sha1']) + '/alerts'
                response = call_api(session, url)

            elif o_type == 'sha1':
                entity = 'files'
                url = url.format(entity=entity, value=o_value) + '/alerts'
                response = call_api(session, url)

            elif o_type == 'domain':
                entity = 'domains'
                url = url.format(entity=entity, value=o_value) + '/alerts'
                response = call_api(session, url)

            elif o_type == 'ip':
                entity = 'ips'
                url = url.format(entity=entity, value=o_value) + '/alerts'
                response = call_api(session, url)

            else:
                raise CTRBadRequestError(f"'{o_type}' type is not supported.")

            if not response or not response.get('value'):
                continue
            values = response['value']

            values.sort(key=lambda x: x['alertCreationTime'], reverse=True)

            count = len(values)

            if count >= current_app.config['CTR_ENTITIES_LIMIT']:
                values = values[:current_app.config['CTR_ENTITIES_LIMIT']]

            for value in values:
                sighting = get_sighting(o_type, o_value, value,
                                        count, entity)
                g.sightings.append(sighting)

    if g.sightings:
        data['sightings'] = format_docs(g.sightings)

    return jsonify_data(data)


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    # Not supported or implemented
    return jsonify_data([])
