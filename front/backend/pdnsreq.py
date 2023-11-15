# pdns_request.py

import requests
from flask import jsonify

from config import api_key

def pdns_request(method, url, data=None):
    headers = {'X-API-Key': api_key, 'Content-Type': 'application/json'}

    try:
        if method == 'GET':
            response = requests.get(url, headers=headers)
        elif method == 'POST':
            response = requests.post(url, headers=headers, json=data)
        elif method == 'PUT':
            response = requests.put(url, headers=headers, json=data)
        elif method == 'DELETE':
            response = requests.delete(url, headers=headers)
        elif method == 'PATCH':
            response = requests.patch(url, headers=headers, json=data)
        else:
            return jsonify({'error': 'Invalid HTTP method'}), 400
    except Exception as e:
        return jsonify({'error': 'Failed to communicate with the external service', 'details': str(e)}), 500

    if response.status_code >= 400:
        return jsonify({'error': 'External service error', 'details': response.text}), response.status_code

    return response
