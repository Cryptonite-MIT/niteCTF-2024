from flask import Flask, request, redirect, render_template, session, make_response, jsonify
import requests
import sqlite3
import hashlib
import uuid
import json
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = uuid.uuid4().hex
OAUTH_URL = os.getenv('OAUTH_URL', 'http://127.0.0.1:5002')
INTERNAL_OAUTH = os.getenv('INTERNAL_OAUTH', 'http://127.0.0.1:5002')
ISSUER_URL = os.getenv('ISSUER_URL', 'http://127.0.0.1:5001')
AUTHORIZATION_ENDPOINT = os.getenv('AUTHORIZATION_ENDPOINT', f'{OAUTH_URL}/authenticate')
TOKEN_ENDPOINT = os.getenv('TOKEN_ENDPOINT', f'{OAUTH_URL}/verifyToken')
USERNAME = os.getenv('USERNAME', "userA")
PASSWORD = os.getenv('PASSWORD', "password")

app.config['MAX_CONTENT_LENGTH'] = 1000  # 1 KB


def init_db():
    conn = sqlite3.connect('/tmp/users.db')
    cursor = conn.cursor()
    # cursor.execute("DROP TABLE IF EXISTS users")
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT NOT NULL PRIMARY KEY,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                       (USERNAME, hashlib.sha256(PASSWORD.encode()).hexdigest()))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    conn.close()


@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        if not session.get("username"):
            return f"You need to be logged in to use this feature... <script>setTimeout(()=>(document.location='/login?redirectTo={request.host_url}'),1500);</script>"

        query = request.form['query']
        # pardon us, we are just starting out
        return redirect(f'https://www.google.com/search?q={query}&btnI=I%27m+Feeling+Lucky&hl=en')
    return render_template('serverB/index.html', loggedin=session.get("username") is not None)


@app.route('/logout')
def logout():
    response = make_response(redirect('/'))
    response.delete_cookie('session_id')
    response.delete_cookie('session')
    return response


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('/tmp/users.db')
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                           (username, hashlib.sha256(password.encode()).hexdigest()))
            conn.commit()
        except sqlite3.IntegrityError:
            error_message = "Uh oh, username is taken!"
            conn.close()
            return render_template('serverB/register.html', error_message=error_message)
        conn.close()
        redirect_url = request.args.get('redirectTo')
        return redirect(f'/login?redirectTo={redirect_url}')
    return render_template('serverB/register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('/tmp/users.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username=? AND password=?",
                       (username, hashlib.sha256(password.encode()).hexdigest()))
        user = cursor.fetchone()
        conn.close()
        
        session['username'] = username
        if not request.args.get('redirectTo'):
            return redirect("/")

        if user:
            session['username'] = username
            if not request.args.get('redirectTo'):
                return redirect("/")
            session_id = hashlib.sha256(str(session).encode()).hexdigest()
            redirect_url = request.args.get('redirectTo')
            scope = request.args.get('scope', 'profile')
            # return redirect(f"{OAUTH_URL}/authenticate?username={username}&redirectTo={redirect_url if redirect_url else request.host_url}&session_id={session_id}&scope={scope}")
            r = requests.get(f"{INTERNAL_OAUTH}/authenticate?username={username}&redirectTo={redirect_url if redirect_url else request.host_url}&session_id={session_id}&scope={scope}", allow_redirects=False)

            return redirect(r.headers['Location'])
        return render_template('serverB/login.html', login_message='Invalid username or password.')
    return render_template('serverB/login.html')


@app.route('/.well-known/openid-configuration')
def openid_configuration():
    return jsonify(
        {
            "issuer": ISSUER_URL,
            "authorization_endpoint": AUTHORIZATION_ENDPOINT,
            "token_endpoint": TOKEN_ENDPOINT,

            "response_types_supported": [
                "code",
                "token",
                "session_id",
                "code token",
                "code session_id",
                "token session_id",
                "code token session_id",
                "none"
            ],
            "subject_types_supported": [
                "public"
            ],
            "id_token_signing_alg_values_supported": [
                "HS256"
            ],
            "scopes_supported": [
                "profile",
                "address",
                "search_history",
                "payment_details"
            ],

            "token_endpoint_auth_methods_supported": [
                "none"
            ],

            "claims_supported": [
                "iss",
                "exp",
                "username",
                "redirect_url",
                "session_id",
                "scope"
            ],

            "code_challenge_methods_supported": [],
            "grant_types_supported": [
                "authorization_code"
            ]
        }
    )


if __name__ == '__main__':
    init_db()
    app.run(port=5001)
