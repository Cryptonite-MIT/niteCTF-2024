from flask import Flask, request, jsonify, redirect
import jwt
import datetime
import string
import random
import uuid

used = set()

app = Flask(__name__)


SECRET_KEY = uuid.uuid4().hex


def generate_jwt(username, redirect_url, session_id, scope='basic'):
    payload = {
        'iss': 'Oogle',
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=5),
        'username': username,
        'redirect_url': redirect_url,
        'session_id': session_id,
        'scope': scope
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return token


@app.route('/authenticate')
def authenticate():
    username = request.args.get('username')
    redirect_url = request.args.get('redirectTo')
    print(f"REDIRECT URL: {redirect_url}")
    session_id = request.args.get('session_id')
    scope = request.args.get('scope', 'profile')
    token = generate_jwt(username, redirect_url, session_id, scope=scope)
    response = redirect(f"{redirect_url}?session_id={session_id}&token={token}")
    response.set_cookie('session_id', session_id)
    return response


@app.route('/verifyToken')
def verify_token():
    token = request.args.get('token')
    task = request.args.get('task')
    if not task:
        if token in used:
            print(used)
            return jsonify({'status': 'error', 'message': 'Token reused'}), 401
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        used.add(token)
        print(used)
        return jsonify({'status': 'success', 'data': decoded})
    except jwt.ExpiredSignatureError:
        return jsonify({'status': 'error', 'message': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'status': 'error', 'message': 'Invalid token'}), 401


if __name__ == '__main__':
    app.run(port=5002)
