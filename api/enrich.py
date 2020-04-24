import uuid
from functools import partial
from flask import Blueprint, current_app

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

resolutions = {
    'detected',
    'blocked',
    'allowed',
    'contained'
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


def get_sighting(observable_type, observable_value, data, count, entity):
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
        'timestamp': data['lastUpdateTime']

    }


@enrich_api.route('/deliberate/observables', methods=['POST'])
def deliberate_observables():
    _ = get_jwt()
    _ = get_observables()
    return jsonify_data({})


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    credentials = get_jwt()
    observables, error = get_observables()
    if error:
        return jsonify_errors(error)

    observables = group_observables(observables)

    if not observables:
        return jsonify_data({})

    data = {}
    sightings = []

    for observable in observables:
        o_value = observable['value']
        o_type = observable['type']

        url = current_app.config['API_URL']

        if o_type == 'sha256':
            entity = 'files'
            get_file_url = url.format(entity=entity, value=o_value)
            response = call_api(get_file_url, credentials)
            o_value = response['sha1']

        elif o_type == 'sha1':
            entity = 'files'

        elif o_type == 'domain':
            entity = 'domains'

        elif o_type == 'ip':
            entity = 'ips'

        else:
            raise CTRBadRequestError(f"{o_type} type is not supported.")

        url = url.format(entity=entity, value=o_value) + '/alerts'

        response = call_api(url, credentials)

        values = response['value']

        values.sort(key=lambda x: x['alertCreationTime'], reverse=True)

        count = len(values)

        if count >= current_app.config['CTR_ENTITIES_LIMIT']:
            values = values[:current_app.config['CTR_ENTITIES_LIMIT']]

        for value in values:
            sighting = get_sighting(o_type, o_value, value,
                                    count, entity)
            sightings.append(sighting)

    if sightings:
        data['sightings'] = format_docs(sightings)

    return jsonify_data(data)


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    # Not supported or implemented
    return jsonify_data([])
