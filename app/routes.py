from flask import Blueprint, render_template, send_from_directory
import os

main = Blueprint('main', __name__)

@main.route('/')
def index():
    return render_template('index.html')

@main.route('/sw.js')
def service_worker():
    static_dir = os.path.join(os.path.dirname(__file__), 'static')
    response = send_from_directory(static_dir, 'sw.js')
    response.headers['Service-Worker-Allowed'] = '/'
    response.headers['Cache-Control'] = 'no-cache'
    return response
