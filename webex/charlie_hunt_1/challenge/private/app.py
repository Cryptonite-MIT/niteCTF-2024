from flask import Flask, render_template, request, jsonify, render_template_string, make_response

PRODUCTS = [
    {'name': 'Milk Chocolate Bar', 'price': 5.99,
        'description': 'Rich and creamy milk chocolate.', 'image': 'milk_chocolate.jpg'},
    {'name': 'Dark Chocolate Bar', 'price': 6.99,
        'description': 'Intense dark chocolate for true cocoa lovers.', 'image': 'dark_chocolate.jpg'},
    {'name': 'White Chocolate Bar', 'price': 5.99,
        'description': 'Smooth and sweet white chocolate.', 'image': 'white_chocolate.jpg'},
    {'name': 'Assorted Truffles', 'price': 12.99,
        'description': 'A selection of our finest truffles.', 'image': 'truffles.jpg'}
]


class RatingProcessor:
        
    def getFlag(self):
        s="nite{3rror5_can_b3_u53ful_s0m3t1m35}"
        return(s)

    def check(self, stars, version, RateProcOb):
        try:
            stars_int = int(stars) if stars else 0

            if stars_int < 0 or stars_int > 5:
                return jsonify({'rating': stars_int, 'error': 'Rating must be in [1,5]'})
            
            if any(char in version for char in BLACK_LIST):
                return jsonify({'error': f"Invalid input! The following characters are not allowed: {', '.join(BLACK_LIST)}"})           

            rendered_output = render_template_string(f"You rated {stars} star(s)")
            return jsonify({'message': rendered_output})
        
        except Exception as e:
            
            if any(char in version for char in BLACK_LIST):
                return jsonify({'error': f"Invalid input! The following characters are not allowed: {', '.join(BLACK_LIST)}"})
            
            debug_info = render_template_string(f"""Please submit this info to developer:     __v: {version}?   ,  class_name: {self.__class__.__name__}  ,   app_image_id: b9d08ae70fa149b29e159c671c9cde7e  ,   err_name: {e.__class__.__name__}
""", e=e)
            return jsonify({"error": debug_info.replace(self.__class__.__name__, "REDACTED")})


app = Flask(__name__)


@app.route('/', methods=['GET'])
def home():
    if request.method == 'POST':
        return make_response(jsonify({'error': 'Method not allowed'}), 405)

    return render_template('index.html')


@app.route('/api/v2/search', methods=['GET', 'POST'])
def search():
    if request.method == 'GET':
        return jsonify({'products': PRODUCTS[:10]})

    query = request.args.get('query', '').lower()
    filtered_products = [
        product for product in PRODUCTS if query in product['name'].lower()] if query else PRODUCTS
    return jsonify({'products': filtered_products})


@app.route('/api/v1/search', methods=['POST'])
def search_v1():
    if request.method == 'GET':
        return make_response(jsonify({'error': 'Method not allowed'}), 405)

    return jsonify({'products': [], "message": "Deprecated!"})


@app.route('/api/v2/review', methods=['POST'])
def review():
    if request.method == 'GET':
        return make_response(jsonify({'error': 'Method not allowed'}), 405)

    data = request.get_json()
    stars = data.get('stars', 0)
    print(f"Received review: {stars} star(s)")
    return jsonify({'message': f'Review submitted successfully: {stars}', 'stars': stars})


BLACK_LIST = ['config', 'globals', 'read', '|join', 'getitem', 'import', 'popen', 'lipsum', 'request', 'os','subclasses',
              'cat','base','builtins','init','cycler','joiner','namespace','shell','.']


@app.route('/api/v1/review', methods=['POST'])
def review_v1():
    if request.method == 'GET':
        return make_response(jsonify({'error': 'Method not allowed'}), 405)

    data = request.get_json()
    stars = data.get('stars', '0')
    version = data.get('__v', 'unknown')

    RateProcOb = RatingProcessor()
    return RateProcOb.check(stars, version,RateProcOb)


if __name__ == '__main__':
    app.run(debug=False)
