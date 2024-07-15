from flask import Flask, render_template, request, jsonify, redirect, url_for, session, make_response
from flask_sqlalchemy import SQLAlchemy
import requests
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
import validators
from OpenSSL import SSL
import socket
from ping3 import ping
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
import time
from datetime import datetime
import base64
import logging
from functools import wraps

# Configure logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:@localhost/monitoring_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'mAbes_pOlri'  # Secret key for session management
db = SQLAlchemy(app)

# Define the MonitoringResult model
class MonitoringResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(256), nullable=False)
    ssl_expiry = db.Column(db.String(64), nullable=False)
    ping_public = db.Column(db.String(64), nullable=False)
    status = db.Column(db.String(64), nullable=False)
    screenshot = db.Column(db.LargeBinary(length=(2**32)-1), nullable=False)  # LONGBLOB
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Define the User model for authentication
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

@app.template_filter('b64encode')
def b64encode_filter(data):
    return base64.b64encode(data).decode('utf-8')

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
        return expiry_date.strftime('%Y-%m-%d')
    except Exception as e:
        logging.error(f"Error checking SSL: {e}")
        return str(e)

# Function to capture website screenshot
def capture_screenshot(url):
    try:
        options = webdriver.ChromeOptions()
        options.add_argument('headless')
        driver = webdriver.Chrome(service=Service("C:/chromedriver-win64/chromedriver.exe"), options=options)
        driver.get(url)
        time.sleep(0)  # Reduce sleep time to 2 seconds
        screenshot_data = driver.get_screenshot_as_png()
        driver.quit()
        return screenshot_data
    except Exception as e:
        logging.error(f"Error capturing screenshot: {e}")
        return None

# Function to make HTTP request
def make_http_request(url):
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as e:
        logging.error(f"Error making HTTP request: {e}")
        raise Exception(f'Error making HTTP request: {str(e)}')

# Decorator to require login and prevent caching
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('index'))
        response = make_response(f(*args, **kwargs))
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    return decorated_function

@app.route('/', methods=['GET', 'POST'])
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))  # Redirect to dashboard if user is already logged in

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        # Query the database for the user
        user = User.query.filter_by(email=email, password=password).first()

        if user:
            # If user exists, store user data in session
            session['user_id'] = user.id
            return redirect(url_for('dashboard'))  # Redirect to dashboard page after successful login
        else:
            return render_template('login.html', error='Invalid credentials')  # Show error message for invalid credentials

    return render_template('login.html')

@app.route('/data')
@login_required
def data():
    results = MonitoringResult.query.order_by(MonitoringResult.id.asc()).all()
    return render_template('data.html', results=results)

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/check', methods=['POST'])
@login_required
def check():
    data = request.json
    url = data.get('url')
    if not validators.url(url):
        return jsonify({'error': 'Invalid URL'}), 400

    try:
        response = make_http_request(url)
        ssl_expiry = check_ssl(url)
        screenshot = capture_screenshot(url)
        ping_public = f"{ping(url.split('//')[-1].split('/')[0]) * 1000:.2f} ms" if ping(url.split('//')[-1].split('/')[0]) else "No response"
        status = "ACTIVE" if response.status_code == 200 else "NON ACTIVE"

        # Check if the URL already exists in the database
        existing_result = MonitoringResult.query.filter_by(url=url).first()

        if existing_result:
            # Update existing record
            existing_result.ssl_expiry = ssl_expiry
            existing_result.ping_public = ping_public
            existing_result.status = status
            existing_result.screenshot = screenshot
        else:
            # Save monitoring result to database
            result = MonitoringResult(
                url=url,
                ssl_expiry=ssl_expiry,
                ping_public=ping_public,
                status=status,
                screenshot=screenshot  # Save raw screenshot data as BLOB
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

@app.route('/dashboard')
@login_required
def dashboard():
    results = MonitoringResult.query.order_by(MonitoringResult.timestamp.desc()).all()
    web_active = MonitoringResult.query.filter_by(status='ACTIVE').count()
    web_non_active = MonitoringResult.query.filter_by(status='NON ACTIVE').count()
    total_web = web_active + web_non_active

    return render_template('dashboard.html', web_active=web_active, web_non_active=web_non_active, total_web=total_web, results=results)

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

# Create tables if they do not exist
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=False)
