from flask import Flask, request, redirect, make_response, render_template, session, jsonify
import requests
import jwt
import uuid
import json
import os

app = Flask(__name__, template_folder="templates")
app.config['SECRET_KEY'] = uuid.uuid4().hex
OAUTH_URL = os.getenv('OAUTH_URL', 'http://127.0.0.1:5002')
SELF_HOST = os.getenv('SELF_HOST', 'http://127.0.0.1:5003')
INTERNAL_OAUTH = os.getenv('INTERNAL_OAUTH', 'http://127.0.0.1:5002')
ISSUER_URL = os.getenv('ISSUER_URL', 'http://127.0.0.1:5001')
USERNAME = os.getenv('USERNAME', "userA")

items_database = {
    USERNAME: [{'id': '1', 'name': 'nite{Idk}', 'price': 10},
               {'id': '2', 'name': "Men's Wonder-13 Sports Running Shoes", 'price': 20}],
    'notuserA': [{'id': '1', 'name': 'Okos Rose Gold Plated Pink Flowers Link Chain Adjustable Size Charm Alloy Bracelet Decorated With Crystals for Girls & Women', 'price': 10},
                 {'id': '2', 'name': "Men's Wonder-13 Sports Running Shoes", 'price': 20}]
}

dummy_db = {}


def generate_jwt(username, exp, scope):
    payload = {
        'iss': 'serverC',
        'exp': exp,
        'username': username,
        'scope': scope
    }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    return token


def verify_token(token):
    try:
        decoded = jwt.decode(
            token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return {'status': 'success', 'data': decoded}
    except jwt.ExpiredSignatureError:
        return {'status': 'error', 'message': 'Token expired'}
    except jwt.InvalidTokenError:
        return {'status': 'error', 'message': 'Invalid token'}


@app.route('/')
def home():
    token = request.cookies.get('token')
    tokenC = request.cookies.get('tokenC')
    if not token:
        return render_template('serverC/indexC.html')
    if tokenC:
        data = verify_token(tokenC)
        if data['status'] == 'success':
            username = data['data']['username']
            items = items_database[USERNAME] if username == USERNAME else items_database['notuserA']
            return render_template('serverC/loggedin.html', username=username, items=items)
        else:
            return redirect('/logout')
    else:
        return redirect('/logout')


@app.route('/login')
def login():
    scope = request.args.get('scope', 'basic')
    redirect_url = f'{SELF_HOST}/callback'
    return redirect(f"{ISSUER_URL}/login?redirectTo={redirect_url}")


@app.route('/callback')
def callback():
    token = request.args.get('token')
    session_id = request.args.get('session_id')
    if session_id and token:
        response1 = requests.get(f"{INTERNAL_OAUTH}/verifyToken?token={token}")
        data = response1.json()
        if data.get('status') == 'success':
            username = data['data']['username']
            exp = data['data']['exp']
            scope = data['data']['scope']
            tokenC = generate_jwt(username, exp, scope)
            response = make_response(redirect('/'))
            response.set_cookie('tokenC', tokenC, httponly=True)
            session['token'] = token
            session['session_id'] = session_id
            response.set_cookie('token', token, httponly=True)
            return response
        else:
            return redirect('/logout')
    return 'Error: No token received', 400


@app.route('/logout')
def logout():
    response = make_response(redirect('/'))
    response.delete_cookie('token')
    response.delete_cookie('tokenC')
    return response


@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    tokenC = request.cookies.get('tokenC')
    if not tokenC:
        return redirect('/login')
    data = verify_token(tokenC)
    if data['status'] != 'success':
        return redirect('/logout')
    username = data['data']['username']
    item_id = request.form.get('item_id')
    if item_id:
        if username not in dummy_db:
            dummy_db[username] = {'cart': []}
        dummy_db[username]['cart'].append(item_id)
        return redirect('/')
    else:
        return 'Error: No item ID provided', 400


@app.route('/view_cart')
def view_cart():
    tokenC = request.cookies.get('tokenC')
    if not tokenC:
        return redirect('/login')
    data = verify_token(tokenC)
    if data['status'] != 'success':
        return redirect('/logout')
    username = data['data']['username']
    if username in dummy_db and 'cart' in dummy_db[username]:
        items_in_cart = [get_item_details(
            username, item_id) for item_id in dummy_db[username]['cart']]
        total_price = sum(item['price'] for item in items_in_cart if item)
        return render_template('serverC/view_cart.html', items=items_in_cart, total_price=total_price)
    else:
        return 'Your shopping cart is empty.'


@app.route('/payment_details')
def payment_details():
    tokenC = request.cookies.get('tokenC')
    if not tokenC:
        return redirect("/login")
    data = verify_token(tokenC)
    if data['status'] != 'success':
        return redirect('/logout')
    if 'payment_details' not in data['data'].get('scope', '').split(','):
        return "Error: Insufficient scope to view payment details.", 403
    return "Flag: nite{y0u_c4nt_h4ck_wh47_y0u_c4n7_f1nd_5550-1309-6672-6224}"


def get_item_details(username, item_id):
    tokenC = request.cookies.get('tokenC')
    if not tokenC:
        return None
    data = verify_token(tokenC)
    if data['status'] != 'success':
        return None
    user_items = items_database[USERNAME] if username == USERNAME else items_database['notuserA']
    if username != USERNAME:
        for item in user_items:
            if item['id'] == item_id:
                return item
    return None


@app.route('/address')
def address():
    tokenC = request.cookies.get('tokenC')
    if not tokenC:
        return redirect('/login')

    data = verify_token(tokenC)
    if data['status'] != 'success':
        return redirect('/logout')

    if 'address' not in data['data'].get('scope', '').split(','):
        return "Error: Insufficient scope to view address details.", 403

    address_details = {
        "name": "John Doe",
        "street": "123 Main Street",
        "city": "Metropolis",
        "state": "NY",
        "zip": "10101"
    }
    return jsonify(address_details)


@app.route('/search_history')
def search_history():
    tokenC = request.cookies.get('tokenC')
    if not tokenC:
        return redirect('/login')

    data = verify_token(tokenC)
    if data['status'] != 'success':
        return redirect('/logout')

    if 'search_history' not in data['data'].get('scope', '').split(','):
        return "Error: Insufficient scope to view search history.", 403

    search_history_data = [
        {"query": "Buy shoes online", "timestamp": "2024-12-05T10:00:00Z"},
        {"query": "Best restaurants near me", "timestamp": "2024-12-04T18:30:00Z"}
    ]
    return jsonify(search_history_data)


if __name__ == '__main__':
    app.run(port=5003)
