# auth.py

from functools import wraps
from flask import request, jsonify
import jwt

from config import SECRET_KEY

def generate_jwt(uid, username):
    payload = {"uid": uid, "username": username}
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return token

def validate(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms='HS256')
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({'error': 'Token is missing'}), 401

        try:
            payload = validate(token)
            if not payload:
                return jsonify({'error': 'Invalid token'}), 401

            user_id = payload['uid']
            username = payload['username']
            return f(user_id, username, *args, **kwargs)

        except Exception as e:
            return jsonify({'error': 'Token validation error', 'details': str(e)}), 401

    return decorated
