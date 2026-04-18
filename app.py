from fileinput import filename
from flask import Flask, render_template, request, send_file, abort, redirect, url_for
import re
from urllib.parse import urlparse
import ipaddress
import requests
import socket
from cryptography.fernet import Fernet
import os 
from database import init_db
from database import get_db_connection
from werkzeug.utils import secure_filename 
from werkzeug.security import generate_password_hash, check_password_hash
from flask import session
from functools import wraps
from flask import flash


BASE_DIR = os.path.abspath(os.path.dirname(__file__))

UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
ENCRYPTED_FOLDER = os.path.join(BASE_DIR, "Encrypted")
DECRYPTED_FOLDER = os.path.join(BASE_DIR, "Decrypted")

app = Flask(__name__)
app.secret_key = os.urandom(24)

init_db()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

def log_file_action(user_id, filename, action):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO file_logs (user_id, file_name, action) VALUES (?, ?, ?)",
        (user_id, filename, action)
    )

    conn.commit()
    conn.close()
    
def check_website_exists(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0'} 
        response = requests.get(url, timeout=5)
        return True, response.status_code
    except requests.exceptions.RequestException:
        return False, None
    
def check_dns(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except:
        return False

@app.route('/')
def home():
    if 'user' in session:
        return redirect(url_for('home_page'))
    return redirect(url_for('login_page'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))

@app.after_request
def add_no_cache_headers(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/home')
@login_required
def home_page():
    return render_template('index.html')

@app.route('/phishing', methods = ['GET', 'POST'])
def phishing():
    if request.method == 'POST':
        return analyze()
    return render_template('phishing.html')

@app.route('/download-decrypted/<filename>')
def download_decrypted(filename):
    file_path = os.path.join(DECRYPTED_FOLDER, filename)
    return send_file(file_path, as_attachment=True)

@app.route('/download-encrypted/<filename>')
def download_encrypted(filename):
    file_path = os.path.join(ENCRYPTED_FOLDER, filename)
    print("Downloading:", file_path)
    return send_file(file_path, as_attachment=True)

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if not username or not password:
            return render_template('login.html', error="All fields required")

        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user['password_hash'], password):
            session['user'] = user['username']
            return redirect(url_for('home_page'))
        else:
            return render_template('login.html', error="Invalid username or password")

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register_page():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        

        if not username or not password:
            return render_template('register.html', error="All fields required")
        
        if len(password) < 6:
            return render_template('register.html', error="Password must be at least 6 characters long")
        
        if not re.search(r"[A-Z]", password):
            return render_template('register.html', error="Must contain uppercase letter")
        
        if not re.search(r"[0-9]", password):
            return render_template('register.html', error="Must contain a number")

        conn = get_db_connection()
        existing_user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if existing_user:
            conn.close()
            return render_template('register.html', error="Username already exists")

        hashed_password = generate_password_hash(password)

        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, hashed_password)
        )
        conn.commit()
        conn.close()

        return redirect(url_for('login_page'))

    return render_template('register.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.form['url']
    if not url.startswith("http"):
        url = "http://" + url
    score = 0
    reasons = []
    
    exists, status_code = check_website_exists(url)

    if not exists:
        score += 30
        reasons.append("Website does not exist or is unreachable.")
    else:
        reasons.append(f"Website is reachable (Status Code: {status_code})")
        
    if status_code == 404:
        score += 10
        reasons.append("Page not found (404).")

    if not url.startswith("https"):
        score += 20
        reasons.append("URL does not use HTTPS.")

    if len(url) > 75:
        score += 15
        reasons.append("URL length is suspiciously long.")
    
    try:
        ipaddress.ip_address(urlparse(url).netloc)
        score += 25
        reasons.append("URL contains an IP address instead of a domain name.")
    except ValueError:
        pass
    
    suspicious_tlds = [".tk", ".ml", ".ga", ".cf"]
    for tld in suspicious_tlds:
        if url.lower().endswith(tld):
            score += 20
            reasons.append(f"URL uses suspicious TLD: {tld}")
            break

    if "@" in url:
        score += 20
        reasons.append("URL contains '@' symbol.")

    if "-" in url:
        score += 10
        reasons.append("URL contains hyphen (-).")

    domain = urlparse(url).netloc
    if not check_dns(domain):
        score += 25
        reasons.append("Domain does not resolve (DNS failure).")
    if domain.count(".") > 2:
        score += 15
        reasons.append("URL contains multiple subdomains.")

    suspicious_keywords = ["login", "verify", "secure", "update", "bank"]
    for word in suspicious_keywords:
        if word in url.lower():
            score += 10
            reasons.append(f"URL contains suspicious keyword: {word}")
            break
        
    if score <= 20:
        risk = "Low Risk ✅"
    elif score <= 50:
        risk = "Medium Risk ⚠️"
    else:
        risk = "High Risk 🚨"

    if not exists and score < 51:
        risk = "High Risk 🚨"
    
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO phishing_logs (target_email, status) VALUES (?, ?)",
        (url, risk)
    )

    conn.commit()
    conn.close()
    return render_template("result.html", url=url, score=score, risk=risk, reasons=reasons)

@app.route('/decrypt', methods=['GET', 'POST'])
@login_required
def decrypt_file():
    if request.method == 'POST':
        encrypted_file = request.files['file']
        key = request.form['key'].strip().encode()

        if encrypted_file and key:
            filename = secure_filename(encrypted_file.filename)
            encrypted_path = os.path.join(UPLOAD_FOLDER, filename)  # ← Use variable, not string
            os.makedirs(UPLOAD_FOLDER, exist_ok=True)
            encrypted_file.save(encrypted_path)
            os.makedirs(DECRYPTED_FOLDER, exist_ok=True)

            try:
                cipher = Fernet(key)
                with open(encrypted_path, "rb") as f:
                    encrypted_data = f.read()
                decrypted_data = cipher.decrypt(encrypted_data)
            except Exception:
                # Show a styled error page instead of plain text
                return render_template("decrypt.html", error="❌ Invalid key or corrupted file. Please try again.")

            decrypted_filename = filename.replace(".enc", "")
            decrypted_path = os.path.join(DECRYPTED_FOLDER, decrypted_filename)

            with open(decrypted_path, "wb") as f:
                f.write(decrypted_data)

            # Get real user ID
            conn = get_db_connection()
            user = conn.execute("SELECT id FROM users WHERE username = ?",
                                (session['user'],)).fetchone()
            conn.close()
            user_id = user['id'] if user else 1

            log_file_action(user_id, decrypted_filename, "decrypt")

            return render_template("decrypt_result.html", filename=decrypted_filename)

    return render_template("decrypt.html")

@app.route('/encrypt', methods=['GET', 'POST'])
@login_required
def encrypt_file():
    if request.method == 'POST':
        file = request.files['file']

        if file:
            # Get the real logged-in user's ID
            conn = get_db_connection()
            user = conn.execute("SELECT id FROM users WHERE username = ?", 
                                (session['user'],)).fetchone()
            conn.close()
            user_id = user['id'] if user else 1

            os.makedirs(UPLOAD_FOLDER, exist_ok=True)
            os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)

            filename = secure_filename(file.filename)
            original_path = os.path.join(UPLOAD_FOLDER, filename)
            file.save(original_path)

            key = Fernet.generate_key()
            cipher = Fernet(key)

            with open(original_path, "rb") as f:
                file_data = f.read()

            encrypted_data = cipher.encrypt(file_data)
            encrypted_filename = filename + ".enc"
            encrypted_path = os.path.join(ENCRYPTED_FOLDER, encrypted_filename)

            with open(encrypted_path, "wb") as f:
                f.write(encrypted_data)

            log_file_action(user_id, file.filename, "encrypt")  # ← Real user ID

            return render_template("encrypt_result.html",
                                   filename=encrypted_filename,
                                   key=key.decode())

    return render_template('encrypt.html')

@app.route('/logs')
def view_logs():
    conn = get_db_connection()
    logs = conn.execute("SELECT * FROM file_logs").fetchall()
    conn.close()

    return str([dict(log) for log in logs])

if __name__ == '__main__':
    app.run(debug=True)