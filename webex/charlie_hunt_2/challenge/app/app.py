from flask import Flask, render_template, request
from flask import Flask, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
import sqlite3
import os
from flask import Flask, render_template, request, jsonify, render_template_string, send_file

app = Flask(__name__, template_folder='./../templates/',
            static_folder='static')
app.secret_key = 'h1myname1smynam31smynameischikach1k4slimsh4dy'
basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, './../products.db')
print(db_path)
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'

# Remove this!!!
# db = SQLAlchemy(app)
# class Products(db.Model):
#     __tablename__ = 'Products'
#     id = db.Column(db.Integer, primary_key=True)
#     name = db.Column(db.String(100), nullable=False)
#     price = db.Column(db.Float, nullable=False)
#     description = db.Column(db.String(200), nullable=False)
#     image = db.Column(db.String(200), nullable=False)

# class Users(db.Model):
#     __tablename__ = 'Users'
#     id = db.Column(db.Integer, primary_key=True)
#     uname = db.Column(db.String(100), nullable=False)
#     passkey = db.Column(db.String(50), nullable=False)

# class Vip_Users(db.Model):
#     __tablename__ = 'Vip_Users'
#     id = db.Column(db.Integer, primary_key=True)
#     uname = db.Column(db.String(100), nullable=False)
#     passkey = db.Column(db.String(50), nullable=False)

# class Vip_Products(db.Model):
#     __tablename__ = 'Vip_Products'
#     id = db.Column(db.Integer, primary_key=True)
#     name = db.Column(db.String(100), nullable=False)
#     price = db.Column(db.Float, nullable=False)
#     description = db.Column(db.String(200), nullable=False)
#     image = db.Column(db.String(200), nullable=False)


def get_db_connection():
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


@app.route('/')
def home():
    query = request.args.get('query', '').lower()
    conn = get_db_connection()
    cursor = conn.cursor()
    sql_query = "SELECT * FROM Products WHERE name LIKE ?;"
    cursor.execute(sql_query, ('%'+query+'%',))
    filtered_products = cursor.fetchall()
    conn.close()
    return render_template('index.html', products=filtered_products)


@app.route('/search', methods=['GET', 'POST'])
def search():
    query = request.args.get('query', '').lower()
    conn = get_db_connection()
    cursor = conn.cursor()
    sql_query = "SELECT * FROM Products WHERE name LIKE ?;"
    cursor.execute(sql_query, ('%'+query+'%',))
    filtered_products = cursor.fetchall()
    conn.close()
    return render_template('results.html', username=(session.get('username', '')), products=filtered_products)


@app.route('/login', methods=['POST', 'GET'])
def login():
    conn = get_db_connection()
    cursor = conn.cursor()
    if request.method == 'GET':
        username = session.get('username')
        password = session.get('password')
        sql_query = "SELECT * FROM Vip_Users WHERE uname = ? AND passkey = ?"
        cursor.execute(sql_query, (username, password))
        result = cursor.fetchone()
        if result:
            user = result['uname']
            session['username'] = user
            session['password'] = result['passkey']
            return redirect(url_for('vip_search'))
        else:
            sql_query = f"SELECT * FROM Users WHERE uname = '{
                username}' AND passkey = '{password}'"
            cursor.execute(sql_query)
            result = cursor.fetchone()
            if result:
                user = result['uname']
                return render_template('search.html', username=user)
    elif request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        sql_query = "SELECT * FROM Vip_Users WHERE uname = ? AND passkey = ?"
        cursor.execute(sql_query, (username, password))
        result = cursor.fetchone()
        if result:
            user = result['uname']
            session['username'] = user
            session['password'] = result['passkey']
            print(user)
            print(result['passkey'])
            query = ""
            conn = get_db_connection()
            cursor = conn.cursor()
            sql_query = "SELECT * FROM Vip_Products WHERE name LIKE ?;"
            cursor.execute(sql_query, ('%'+query+'%',))
            filtered_products = cursor.fetchall()
            conn.close()
            return render_template('vip_search.html', username=user, products=filtered_products)
        else:
            sql_query = f"SELECT * FROM Users WHERE uname = ? AND passkey = ?"
            cursor.execute(sql_query, (username, password,))
            result = cursor.fetchone()
            if result:
                user = result['uname']
                session['username'] = user
                print(user)
                print(result['passkey'])
                query = ""
                conn = get_db_connection()
                cursor = conn.cursor()
                sql_query = "SELECT * FROM Products WHERE name LIKE ?;"
                cursor.execute(sql_query, ('%'+query+'%',))
                filtered_products = cursor.fetchall()
                conn.close()
                return render_template('search.html', username=user)
    conn.close()
    return render_template('login.html')


@app.route('/vip_search', methods=['GET', 'POST'])
def vip_search():
    if request.method == 'GET':
        username = session.get('username')
        password = session.get('password')
        sql_query = "SELECT * FROM Vip_Users WHERE uname = ? AND passkey = ?"
        cursor.execute(sql_query, (username, password))
        result = cursor.fetchone()
        if not result:
            return redirect(url_for('login'))
        query = request.args.get('query', '').lower()
        conn = get_db_connection()
        cursor = conn.cursor()
        sql_query = "SELECT * FROM Vip_Products WHERE name LIKE ?;"
        cursor.execute(sql_query, ('%'+query+'%',))
        filtered_products = cursor.fetchall()
        conn.close()
        return render_template('vip_search.html', username=username, products=filtered_products)
    elif request.method == 'POST':
        username = request.form.get('username')
        if not username:
            return redirect(url_for('login'))
        query = request.args.get('query', '').lower()
        conn = get_db_connection()
        cursor = conn.cursor()
        sql_query = "SELECT * FROM Products WHERE name LIKE ?;"
        cursor.execute(sql_query, ('%'+query+'%',))
        filtered_products = cursor.fetchall()
        conn.close()
        return render_template('results.html', username=username, products=filtered_products)
    return redirect(url_for('login'))


@app.route('/version2/user_review', methods=['POST'])
def user_review():
    data = request.get_json()
    stars = data.get('stars', 0)
    print(f"Received review: {stars} star(s)")
    return jsonify({'message': 'Review submitted successfully', 'stars': stars})


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=5000)
