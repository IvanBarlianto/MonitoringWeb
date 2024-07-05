from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import requests
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
import validators
from OpenSSL import SSL
import socket
from ping3 import ping
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
import time
from datetime import datetime
import base64

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:@localhost/monitoring_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Define the MonitoringResult model
class MonitoringResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(256), nullable=False)
    ssl_expiry = db.Column(db.String(64), nullable=False)
    ping_public = db.Column(db.String(64), nullable=False)
    status = db.Column(db.String(64), nullable=False)
    screenshot = db.Column(db.LargeBinary, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Function to check SSL expiry date
def check_ssl(url):
    try:
        domain = url.split('//')[-1].split('/')[0]
        context = SSL.Context(SSL.TLSv1_2_METHOD)
        conn = SSL.Connection(context, socket.socket(socket.AF_INET))
        conn.connect((domain, 443))
        conn.do_handshake()
        cert = conn.get_peer_certificate()
        expiry_date_str = cert.get_notAfter().decode('utf-8')
        expiry_date = datetime.strptime(expiry_date_str, '%Y%m%d%H%M%SZ')
        return expiry_date.strftime('%d-%m-%Y')
    except Exception as e:
        return str(e)

# Function to capture website screenshot
def capture_screenshot(url):
    options = webdriver.ChromeOptions()
    options.add_argument('headless')
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
    driver.get(url)
    time.sleep(10)  # Add a delay to ensure page fully loads before taking screenshot
    screenshot_data = driver.get_screenshot_as_png()
    driver.quit()
    return screenshot_data

# Function to make HTTP request
def make_http_request(url):
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session = requests.Session()
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    try:
        response = session.get(url, timeout=30)
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as e:
        raise Exception(f'Error making HTTP request: {str(e)}')

# Route for index page
@app.route('/data')
def data():
    return render_template('data.html')

# Route for checking website
@app.route('/check', methods=['POST'])
def check():
    data = request.json
    url = data.get('url')
    if not validators.url(url):
        return jsonify({'error': 'Invalid URL'}), 400

    try:
        response = make_http_request(url)
        ssl_expiry = check_ssl(url)
        screenshot = capture_screenshot(url)
        ping_public, status = ping_and_status_website(url)

        # Save monitoring result to database
        result = MonitoringResult(
            url=url,
            ssl_expiry=ssl_expiry,
            ping_public=ping_public,
            status=status,
            screenshot=screenshot
        )
        db.session.add(result)
        db.session.commit()

        return jsonify({
            'ssl_expiry': ssl_expiry,
            'screenshot': base64.b64encode(screenshot).decode('utf-8'),
            'ping_public': ping_public,
            'status': status
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Route for dashboard
@app.route('/dashboard')
def dashboard():
    results = MonitoringResult.query.order_by(MonitoringResult.timestamp.desc()).all()
    web_active = MonitoringResult.query.filter_by(status='ACTIVE').count()
    web_non_active = MonitoringResult.query.filter_by(status='NON ACTIVE').count()
    jumlah_web = web_active + web_non_active

    return render_template('dashboard.html', web_active=web_active, web_non_active=web_non_active, jumlah_web=jumlah_web, results=results)

# Create tables if they do not exist
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
