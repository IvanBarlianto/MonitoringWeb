from flask import Flask, render_template, request, jsonify, redirect, url_for, session, make_response
from flask_sqlalchemy import SQLAlchemy
import requests
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
import validators
from OpenSSL import SSL
import socket
from ping3 import ping
import time
from datetime import datetime
import base64
import logging
from functools import wraps
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By

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
    ping_local = db.Column(db.String(64), nullable=False)
    ping_public = db.Column(db.String(64), nullable=False)
    status = db.Column(db.String(64), nullable=False)
    screenshot = db.Column(db.LargeBinary(length=(2**32)-1), nullable=True)  # LONGBLOB
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Define the User model for authentication
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(10), nullable=False, default='user')  # Add role field

@app.template_filter('b64encode')
def b64encode_filter(data):
    if data is None:
        return ''
    return base64.b64encode(data).decode('utf-8')

# Function to perform local ping
def ping_local(domain):
    try:
        ping_time = ping(domain)
        return f"{ping_time * 1000:.2f} ms" if ping_time else "No response"
    except Exception as e:
        logging.error(f"Error performing local ping: {e}")
        return "Error"

def ping_public(domain):
    try:
        # Measure the response time from the public URL
        start_time = time.time()
        response = requests.get(f'http://{domain}', timeout=30)
        elapsed_time = time.time() - start_time
        
        if response.status_code == 200:
            return f"{elapsed_time * 1000:.2f} ms"  # Convert seconds to milliseconds
        return "No response"
    except requests.exceptions.RequestException as e:
        logging.error(f"Error performing public ping: {e}")
        return "Error"

# Function to check SSL expiry date
def check_ssl(domain):
    try:
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
        return "-"  # Return "-" in case of error


# Function to capture website screenshot
def capture_screenshot(url):
    try:
        options = webdriver.ChromeOptions()
        options.add_argument('headless')
        options.add_argument('ignore-certificate-errors')  # Ignore SSL certificate errors
        options.add_argument('user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36')
        
        driver = webdriver.Chrome(service=Service("C:/chromedriver-win64/chromedriver.exe"), options=options)
        driver.get(url)
        
        # Wait for a specific element to load
        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, 'body')))
        
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
        return None

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
    user = User.query.get(session['user_id'])
    results = MonitoringResult.query.order_by(MonitoringResult.id.asc()).all()
    
    if user.role == 'admin':
        return render_template('admin.html', results=results)
    else:
        return render_template('data.html', results=results)

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/check', methods=['POST'])
@login_required
def check():
    data = request.json
    url = data.get('url')

    # Add https:// if missing and store URL without the protocol
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'https://' + url

    domain = url.split('//')[-1].split('/')[0]

    if not validators.url(url):
        return jsonify({'error': 'Invalid URL'}), 400

    try:
        response = make_http_request(url)
        ssl_expiry = check_ssl(domain)
        screenshot = capture_screenshot(url)
        
        # Set a default value if screenshot is None
        if screenshot == b'-':
            screenshot = b'-'  

        # Perform ping operations
        ping_local_result = ping_local(domain)
        ping_public_result = ping_public(domain)
        
        # Initialize status
        status = "ACTIVE" if response else "NON ACTIVE"
        
        # If response is None, set status to the error message
        if response is None:
            status = "NON ACTIVE"

        # Check if the URL already exists in the database
        existing_result = MonitoringResult.query.filter_by(url=domain).first()

        if existing_result:
            # Update existing record
            existing_result.ssl_expiry = ssl_expiry
            existing_result.ping_local = ping_local_result
            existing_result.ping_public = ping_public_result
            existing_result.status = status
            existing_result.screenshot = screenshot
        else:
            # Save monitoring result to database
            result = MonitoringResult(
                url=domain,
                ssl_expiry=ssl_expiry,
                ping_local=ping_local_result,
                ping_public=ping_public_result,
                status=status,
                screenshot=screenshot  # Save raw screenshot data as BLOB
            )
            db.session.add(result)

        db.session.commit()

        return jsonify({
            'ssl_expiry': ssl_expiry,
            'screenshot': base64.b64encode(screenshot).decode('utf-8'),
            'ping_local': ping_local_result,
            'ping_public': ping_public_result,
            'status': status
        })
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/dashboard')
@login_required
def dashboard():
    results = MonitoringResult.query.order_by(MonitoringResult.timestamp.desc()).all()
    web_active = MonitoringResult.query.filter_by(status='ACTIVE').count()
    web_non_active = MonitoringResult.query.filter_by(status='NON ACTIVE').count()
    total_web = web_active + web_non_active

    return render_template('dashboard.html', web_active=web_active, web_non_active=web_non_active, total_web=total_web, results=results)

# @app.route('/profile')
# @login_required
# def profile():
#     return render_template('profile.html')

@app.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

@app.route('/delete/<int:id>', methods=['DELETE'])
def delete_entry(id):
    result = MonitoringResult.query.get(id)
    if result:
        db.session.delete(result)
        db.session.commit()
        return jsonify({'message': 'Entry deleted successfully'}), 200
    return jsonify({'error': 'Entry not found'}), 404

@app.route('/recheck_all', methods=['POST'])
@login_required
def recheck_all():
    try:
        results = MonitoringResult.query.all()
        for result in results:
            response = make_http_request('https://' + result.url)
            ssl_expiry = check_ssl(result.url)
            screenshot = capture_screenshot('https://' + result.url)
            
            if screenshot == b'-':
                screenshot = b'-'

            # Perform ping operations
            ping_local_result = ping_local(result.url)
            ping_public_result = ping_public(result.url)

            status = "ACTIVE" if response else "NON ACTIVE"
            
            if response is None:
                status = "NON ACTIVE"

            result.ssl_expiry = ssl_expiry
            result.ping_local = ping_local_result
            result.ping_public = ping_public_result
            result.status = status
            result.screenshot = screenshot

        db.session.commit()
        return jsonify({'message': 'Rechecked all URLs successfully'}), 200
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/recheck_selected', methods=['POST'])
@login_required
def recheck_selected():
    data = request.json
    urls = data.get('urls', [])
    
    if not urls:
        return jsonify({'error': 'No URLs provided'}), 400
    
    try:
        for url in urls:
            result = MonitoringResult.query.filter_by(url=url).first()
            if result:
                response = make_http_request('https://' + result.url)
                ssl_expiry = check_ssl(result.url)
                screenshot = capture_screenshot('https://' + result.url)
                
                if screenshot == b'-':
                    screenshot = b'-'

                # Perform ping operations
                ping_local_result = ping_local(result.url)
                ping_public_result = ping_public(result.url)

                status = "ACTIVE" if response else "NON ACTIVE"
                
                if response is None:
                    status = "NON ACTIVE"

                result.ssl_expiry = ssl_expiry
                result.ping_local = ping_local_result
                result.ping_public = ping_public_result
                result.status = status
                result.screenshot = screenshot

        db.session.commit()
        return jsonify({'message': 'Rechecked selected URLs successfully'}), 200
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return jsonify({'error': str(e)}), 500

# Create tables if they do not exist
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=False)