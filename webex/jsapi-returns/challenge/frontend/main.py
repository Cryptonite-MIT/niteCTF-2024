from flask import Flask, send_file, send_from_directory
import os

app = Flask(__name__)

@app.route("/")
def index():
    return send_file(os.path.join(os.getcwd(), 'index.html'))

@app.route("/<string:filename>")
def handle_req(filename):
    return send_from_directory('.', filename)

@app.errorhandler(404)
def page_not_found(e):
    return send_file(os.path.join(os.getcwd(), 'solution.txt'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
