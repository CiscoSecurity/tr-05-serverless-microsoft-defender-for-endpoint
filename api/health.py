import requests
from flask import Blueprint

from api.utils import get_jwt, jsonify_data, call_api

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    credentials = get_jwt()
    url = 'https://api.securitycenter.windows.com/api/exposureScore'
    with requests.Session() as session:
        call_api(session, url, credentials)
    return jsonify_data({'status': 'ok'})
