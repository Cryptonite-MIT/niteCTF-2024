import os
from flask import Flask, request, jsonify, g, send_from_directory
import sqlite3
import bcrypt
import jwt
import datetime
from functools import wraps
from cryptography.fernet import Fernet
import base64
import hashlib

app = Flask(__name__)

app.config['DATABASE'] = './notes_app.db'
app.config['FDRP_DATABASE'] = './notes_app_fdrp.db'

app.config['SECRET_KEY'] = 'HARDPASSWORD'

app.config['JWT_SECRET_KEY'] = os.environ['JWT_SECRET_KEY']
app.config['FDRP_JWT_SECRET_KEY'] = os.environ['FDRP_JWT_SECRET_KEY']

RESTRICTED = ["1"]


def derive_key(password):
    key = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(key[:32])


def encrypt(text, password):
    text = str(text)
    key = derive_key(password)
    cipher = Fernet(key)
    return cipher.encrypt(text.encode()).decode()


def decrypt(encrypted_text, password):
    encrypted_text = str(encrypted_text)
    key = derive_key(password)
    cipher = Fernet(key)
    return cipher.decrypt(encrypted_text.encode()).decode()


@app.route("/")
def base():
    return send_from_directory('dist/', 'index.html')


@app.route('/uploads/')
def list_files():
    files = os.listdir("uploads")
    # SORRY, BUT IG NO ONE WILL LOOK AT IT SO ITS FINE
    html = '<h1>Uploaded Files</h1>'
    html += '<ul>'
    for file in files:
        html += f'<li><a href="/uploads/{file}">{file}</a></li>'
    html += '</ul>'

    return html


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory('uploads', filename)


@app.route("/<path:path>")
def home(path):
    return send_from_directory('dist/', path)


def get_db(fdrp=False):
    if fdrp:
        db = getattr(g, '_database_fdrp', None)
        if db is None:
            db = g._database_fdrp = sqlite3.connect(
                app.config['FDRP_DATABASE'])
        return db

    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])
    return db


def query_db(query, args=(), one=False, fdrp=False):
    cur = get_db(fdrp=fdrp).execute(query, args)
    rv = cur.fetchall()
    cur.close()
    get_db(fdrp=fdrp).commit()
    return (rv[0] if rv else None) if one else rv


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def create_tables():
    with app.app_context():
        db = get_db()
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                tags TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        db.commit()

        db = get_db(fdrp=True)
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')

        db.execute('''
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                tags TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        db.commit()


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
        if not token:
            return jsonify({"message": "Token is missing!"}), 401
        try:
            data = jwt.decode(
                token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
            user = query_db('SELECT * FROM users WHERE id = ?',
                            decrypt(data['user_id'], app.config['SECRET_KEY']),
                            one=True)
            fdrp = False
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError) as e:
            # FDRP
            try:
                data = jwt.decode(
                    token, app.config['FDRP_JWT_SECRET_KEY'], algorithms=["HS256"])
                user = query_db('SELECT * FROM users WHERE id = ?',
                                decrypt(data['user_id'],
                                        app.config['SECRET_KEY']),
                                one=True, fdrp=True)
                fdrp = True
            except (jwt.ExpiredSignatureError, jwt.InvalidTokenError) as e:
                return jsonify({"message": "Token is invalid!!"}), 401
        return f(user, fdrp, *args, **kwargs)
    return decorated


@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    hashed_password = bcrypt.hashpw(
        data['password'].encode('utf-8'), bcrypt.gensalt())
    hashed_FDRP_password = bcrypt.hashpw(
        data['FDRPpassword'].encode('utf-8'), bcrypt.gensalt())

    try:
        query_db('INSERT INTO users (username, password) VALUES (?, ?)', [
                 data['username'], hashed_password.decode('utf-8')])
        query_db('INSERT INTO users (username, password) VALUES (?, ?)', [
                 data['username'], hashed_FDRP_password.decode('utf-8')], fdrp=True)
    except sqlite3.IntegrityError:
        return jsonify({"message": "Username already exists"}), 400
    return jsonify({"message": "User registered"}), 201


@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    user = query_db('SELECT * FROM users WHERE username = ?',
                    [data['username']], one=True)
    if user and bcrypt.checkpw(data['password'].encode('utf-8'), user[2].encode('utf-8')):
        token = jwt.encode({
            'user_id': encrypt(user[0], app.config['SECRET_KEY']),
            'exp': int((datetime.datetime.utcnow() + datetime.timedelta(hours=1)).replace(minute=0, second=0, microsecond=0).timestamp())
        }, app.config['JWT_SECRET_KEY'], algorithm="HS256")
        return jsonify({"token": token, "real": True}), 200

    # FDRP
    user = query_db('SELECT * FROM users WHERE username = ?',
                    [data['username']], one=True, fdrp=True)
    if user and bcrypt.checkpw(data['password'].encode('utf-8'), user[2].encode('utf-8')):
        token = jwt.encode({
            'user_id': encrypt(user[0], app.config['SECRET_KEY']),
            'exp': int((datetime.datetime.utcnow() + datetime.timedelta(hours=1)).replace(minute=0, second=0, microsecond=0).timestamp())
        }, app.config['FDRP_JWT_SECRET_KEY'], algorithm="HS256")
        return jsonify({"token": token, "real": False}), 200

    return jsonify({"message": "Invalid credentials"}), 401


@app.route('/api/notes', methods=['POST'])
@token_required
def add_note(user, fdrp):
    if decrypt(user, app.config['SECRET_KEY']) in RESTRICTED:
        return jsonify({"message": "Something went wrong"}), 400
    data = request.json
    query_db('INSERT INTO notes (user_id, title, content, tags) VALUES (?, ?, ?, ?)', [
             user[0], data['title'], data['content'], data.get('tags', '')], fdrp=fdrp)
    return jsonify({"message": "Note added successfully"}), 201


@app.route('/api/notes/<int:note_id>', methods=['PUT'])
@token_required
def edit_note(user, fdrp, note_id):
    if decrypt(user, app.config['SECRET_KEY']) in RESTRICTED:
        return jsonify({"message": "Something went wrong"}), 400
    data = request.json
    note = query_db('SELECT * FROM notes WHERE id = ? AND user_id = ?',
                    [note_id, user[0]], one=True, fdrp=fdrp)
    if not note:
        return jsonify({"message": "Note not found"}), 404
    query_db('UPDATE notes SET title = ?, content = ?, tags = ? WHERE id = ? AND user_id = ?',
             [data['title'], data['content'], data.get('tags', ''), note_id, user[0]], fdrp=fdrp)
    return jsonify({"message": "Note updated successfully"}), 200


@app.route('/api/notes/<int:note_id>', methods=['DELETE'])
@token_required
def delete_note(user, fdrp, note_id):
    if decrypt(user, app.config['SECRET_KEY']) in RESTRICTED:
        return jsonify({"message": "Cannot delete"}), 400
    note = query_db('SELECT * FROM notes WHERE id = ? AND user_id = ?',
                    [note_id, user[0]], one=True, fdrp=fdrp)
    if not note:
        return jsonify({"message": "Note not found"}), 404
    query_db('DELETE FROM notes WHERE id = ? AND user_id = ?',
             [note_id, user[0]], fdrp=fdrp)
    return jsonify({"message": "Note deleted successfully"}), 200


@app.route('/api/notes', methods=['GET'])
@token_required
def get_notes(user, fdrp):
    query = 'SELECT * FROM notes WHERE user_id = ?'
    args = [user[0]]
    if 'tag' in request.args:
        query += ' AND tags LIKE ?'
        args.append(f"%{request.args['tag']}%")
    if 'search' in request.args:
        query += ' AND (title LIKE ? OR content LIKE ?)'
        args.append(f"%{request.args['search']}%")
        args.append(f"%{request.args['search']}%")
    notes = query_db(query, args, fdrp=fdrp)
    return jsonify(notes), 200


if __name__ == '__main__':
    create_tables()
    app.run(debug=False)
