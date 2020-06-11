from flask import Blueprint

from api.utils import get_jwt, jsonify_data
from api.client import Client

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    credentials = get_jwt()
    url = 'https://api.securitycenter.windows.com/api/exposureScore'
    client = Client(credentials)
    client.open_session()
    client.call_api(url)
    return jsonify_data({'status': 'ok'})
