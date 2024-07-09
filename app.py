from flask import Flask, render_template, request, jsonify
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
import time  # Added for delay
from datetime import datetime  # Added for date formatting

app = Flask(__name__)

def ping_and_status_website(url):
    domain = url.split('//')[-1].split('/')[0]
    response_time = ping(domain)
    if response_time is not None:
        return f"{response_time} ms", "ACTIVE"
    else:
        return "Request timed out", "NON ACTIVE"

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

def capture_screenshot(url):
    options = webdriver.ChromeOptions()
    options.add_argument('headless')
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
    driver.get(url)
    
    # Add a delay to ensure page fully loads before taking screenshot
    time.sleep(10)
    
    screenshot_path = f'static/screenshots/{url.replace("https://", "").replace("http://", "").replace("/", "_")}.png'
    driver.save_screenshot(screenshot_path)
    driver.quit()
    return screenshot_path

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

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/data')
def data():
    return render_template('data.html')

@app.route('/dashboard')
def dashboard():
    # Data simulasi
    web_active = 5
    web_non_active = 3
    jumlah_web = web_active + web_non_active

    return render_template('dashboard.html', web_active=web_active, web_non_active=web_non_active, jumlah_web=jumlah_web)

@app.route('/profile')
def profile():
    return render_template('profile.html')

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/check', methods=['POST'])
def check():
    data = request.json
    url = data.get('url')
    if not validators.url(url):
        return jsonify({'error': 'Invalid URL'}), 400

    try:
        response = make_http_request(url)
        # Proceed with further processing
        ssl_expiry = check_ssl(url)
        screenshot = capture_screenshot(url)
        ping_public, status = ping_and_status_website(url)

        return jsonify({
            'ssl_expiry': ssl_expiry,
            'screenshot': screenshot,
            'ping_public': ping_public,
            'status': status
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
