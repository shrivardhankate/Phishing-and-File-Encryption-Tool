from flask import Flask, render_template, request, send_file, redirect, url_for, session, flash
import re
from urllib.parse import urlparse
import ipaddress
import requests
import socket
from cryptography.fernet import Fernet
import os
from database import init_db, get_db_connection
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER   = os.path.join(BASE_DIR, "uploads")
ENCRYPTED_FOLDER = os.path.join(BASE_DIR, "Encrypted")
DECRYPTED_FOLDER = os.path.join(BASE_DIR, "Decrypted")

app = Flask(__name__)
app.secret_key = 'cybershield_secret_2026_changeme'

init_db()


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated

def get_current_user():
    if 'user' not in session:
        return None
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (session['user'],)).fetchone()
    conn.close()
    return user

def log_file_action(user_id, filename, action, encryption_key=None):
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO file_logs (user_id, file_name, action, encryption_key) VALUES (?, ?, ?, ?)",
        (user_id, filename, action, encryption_key)
    )
    conn.commit()
    conn.close()

def check_website_exists(url):
    try:
        response = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
        return True, response.status_code
    except requests.exceptions.RequestException:
        return False, None

def check_dns(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except:
        return False


@app.after_request
def no_cache(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


@app.route('/')
def home():
    if 'user' in session:
        return redirect(url_for('home_page'))
    return redirect(url_for('login_page'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if 'user' in session:
        return redirect(url_for('home_page'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        if not username or not password:
            return render_template('login.html', error="All fields are required.")
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password_hash'], password):
            session['user'] = user['username']
            return redirect(url_for('home_page'))
        return render_template('login.html', error="Invalid username or password.")
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register_page():
    if 'user' in session:
        return redirect(url_for('home_page'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        email    = request.form.get('email', '').strip()
        if not username or not password:
            return render_template('register.html', error="Username and password are required.")
        if len(password) < 6:
            return render_template('register.html', error="Password must be at least 6 characters.")
        if not re.search(r"[A-Z]", password):
            return render_template('register.html', error="Password must contain at least one uppercase letter.")
        if not re.search(r"[0-9]", password):
            return render_template('register.html', error="Password must contain at least one number.")
        conn = get_db_connection()
        existing = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if existing:
            conn.close()
            return render_template('register.html', error="Username already taken. Please choose another.")
        conn.execute(
            "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), email)
        )
        conn.commit()
        conn.close()
        return redirect(url_for('login_page'))
    return render_template('register.html')

@app.route('/home')
@login_required
def home_page():
    return render_template('index.html')


@app.route('/profile')
@login_required
def profile_page():
    user = get_current_user()
    conn = get_db_connection()

    encrypt_logs = conn.execute(
        "SELECT * FROM file_logs WHERE user_id = ? AND action = 'encrypt' ORDER BY timestamp DESC",
        (user['id'],)
    ).fetchall()

    decrypt_logs = conn.execute(
        "SELECT * FROM file_logs WHERE user_id = ? AND action = 'decrypt' ORDER BY timestamp DESC",
        (user['id'],)
    ).fetchall()

    phishing_logs = conn.execute(
        "SELECT * FROM phishing_logs WHERE user_id = ? ORDER BY timestamp DESC",
        (user['id'],)
    ).fetchall()

    conn.close()
    return render_template('profile.html',
                           user=user,
                           encrypt_logs=encrypt_logs,
                           decrypt_logs=decrypt_logs,
                           phishing_logs=phishing_logs)

@app.route('/profile/update-details', methods=['POST'])
@login_required
def update_details():
    user = get_current_user()
    new_username = request.form.get('username', '').strip()
    new_email    = request.form.get('email', '').strip()

    if not new_username:
        return redirect(url_for('profile_page'))

    conn = get_db_connection()
    # Check username not taken by another user
    existing = conn.execute(
        "SELECT id FROM users WHERE username = ? AND id != ?",
        (new_username, user['id'])
    ).fetchone()
    if existing:
        conn.close()
        return render_template('profile.html',
                               user=user, error_details="Username already taken.",
                               encrypt_logs=[], decrypt_logs=[], phishing_logs=[])

    conn.execute(
        "UPDATE users SET username = ?, email = ? WHERE id = ?",
        (new_username, new_email, user['id'])
    )
    conn.commit()
    conn.close()
    session['user'] = new_username   # keep session in sync
    return redirect(url_for('profile_page'))

@app.route('/profile/change-password', methods=['POST'])
@login_required
def change_password():
    user = get_current_user()
    current  = request.form.get('current_password', '').strip()
    new_pass = request.form.get('new_password', '').strip()
    confirm  = request.form.get('confirm_password', '').strip()

    conn = get_db_connection()
    encrypt_logs  = conn.execute("SELECT * FROM file_logs WHERE user_id=? AND action='encrypt' ORDER BY timestamp DESC", (user['id'],)).fetchall()
    decrypt_logs  = conn.execute("SELECT * FROM file_logs WHERE user_id=? AND action='decrypt' ORDER BY timestamp DESC", (user['id'],)).fetchall()
    phishing_logs = conn.execute("SELECT * FROM phishing_logs WHERE user_id=? ORDER BY timestamp DESC", (user['id'],)).fetchall()
    conn.close()

    def fail(msg):
        return render_template('profile.html', user=user, error_password=msg,
                               encrypt_logs=encrypt_logs, decrypt_logs=decrypt_logs,
                               phishing_logs=phishing_logs)

    if not check_password_hash(user['password_hash'], current):
        return fail("Current password is incorrect.")
    if len(new_pass) < 6:
        return fail("New password must be at least 6 characters.")
    if not re.search(r"[A-Z]", new_pass):
        return fail("New password must contain an uppercase letter.")
    if not re.search(r"[0-9]", new_pass):
        return fail("New password must contain a number.")
    if new_pass != confirm:
        return fail("New passwords do not match.")

    conn = get_db_connection()
    conn.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                 (generate_password_hash(new_pass), user['id']))
    conn.commit()
    conn.close()
    return render_template('profile.html', user=user, success_password="Password changed successfully!",
                           encrypt_logs=encrypt_logs, decrypt_logs=decrypt_logs,
                           phishing_logs=phishing_logs)


@app.route('/encrypt', methods=['GET', 'POST'])
@login_required
def encrypt_file():
    if request.method == 'POST':
        file = request.files.get('file')
        if file and file.filename:
            user = get_current_user()
            os.makedirs(UPLOAD_FOLDER, exist_ok=True)
            os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)

            filename = secure_filename(file.filename)
            original_path = os.path.join(UPLOAD_FOLDER, filename)
            file.save(original_path)

            key = Fernet.generate_key()
            cipher = Fernet(key)

            with open(original_path, "rb") as f:
                encrypted_data = cipher.encrypt(f.read())

            enc_filename = filename + ".enc"
            with open(os.path.join(ENCRYPTED_FOLDER, enc_filename), "wb") as f:
                f.write(encrypted_data)

            log_file_action(user['id'], filename, "encrypt", encryption_key=key.decode())

            return render_template("encrypt_result.html", filename=enc_filename, key=key.decode())

    return render_template('encrypt.html')

@app.route('/decrypt', methods=['GET', 'POST'])
@login_required
def decrypt_file():
    if request.method == 'POST':
        encrypted_file = request.files.get('file')
        key_str = request.form.get('key', '').strip()

        if encrypted_file and key_str:
            user = get_current_user()
            os.makedirs(UPLOAD_FOLDER, exist_ok=True)
            os.makedirs(DECRYPTED_FOLDER, exist_ok=True)

            filename = secure_filename(encrypted_file.filename)
            enc_path = os.path.join(UPLOAD_FOLDER, filename)
            encrypted_file.save(enc_path)

            try:
                cipher = Fernet(key_str.encode())
                with open(enc_path, "rb") as f:
                    decrypted_data = cipher.decrypt(f.read())
            except Exception:
                return render_template("decrypt.html", error="❌ Invalid key or corrupted file. Please check and try again.")

            dec_filename = filename.replace(".enc", "")
            with open(os.path.join(DECRYPTED_FOLDER, dec_filename), "wb") as f:
                f.write(decrypted_data)

            log_file_action(user['id'], dec_filename, "decrypt")
            return render_template("decrypt_result.html", filename=dec_filename)

    return render_template("decrypt.html")

@app.route('/phishing', methods=['GET', 'POST'])
@login_required
def phishing():
    if request.method == 'POST':
        return analyze()
    return render_template('phishing.html')

@app.route('/analyze', methods=['POST'])
@login_required
def analyze():
    url = request.form.get('url', '').strip()
    if not url.startswith("http"):
        url = "http://" + url

    score = 0
    reasons = []

    exists, status_code = check_website_exists(url)

    if not exists:
        score += 30
        reasons.append("⚠️ Website does not exist or is unreachable.")
    else:
        reasons.append(f"✅ Website is reachable (Status {status_code}).")

    if status_code == 404:
        score += 10
        reasons.append("⚠️ Page not found (404 error).")

    if not url.startswith("https"):
        score += 20
        reasons.append("⚠️ URL does not use HTTPS (not secure).")

    if len(url) > 75:
        score += 15
        reasons.append("⚠️ URL is suspiciously long.")

    try:
        ipaddress.ip_address(urlparse(url).netloc)
        score += 25
        reasons.append("🚨 URL uses an IP address instead of a domain name.")
    except ValueError:
        pass

    for tld in [".tk", ".ml", ".ga", ".cf"]:
        if url.lower().endswith(tld):
            score += 20
            reasons.append(f"⚠️ URL uses a suspicious free TLD: {tld}")
            break

    if "@" in url:
        score += 20
        reasons.append("🚨 URL contains '@' symbol — a common phishing trick.")

    domain = urlparse(url).netloc
    if not check_dns(domain):
        score += 25
        reasons.append("🚨 Domain does not resolve (DNS failure).")
    if domain.count(".") > 2:
        score += 15
        reasons.append("⚠️ URL has multiple subdomains — possibly spoofing a real site.")

    for word in ["login", "verify", "secure", "update", "bank", "account", "confirm"]:
        if word in url.lower():
            score += 10
            reasons.append(f"⚠️ URL contains suspicious keyword: '{word}'")
            break

    if score <= 20:
        risk = "Low Risk"
    elif score <= 50:
        risk = "Medium Risk"
    else:
        risk = "High Risk"

    if not exists and score < 51:
        risk = "High Risk"

    user = get_current_user()
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO phishing_logs (user_id, target_url, score, status) VALUES (?, ?, ?, ?)",
        (user['id'] if user else None, url, score, risk)
    )
    conn.commit()
    conn.close()

    return render_template("result.html", url=url, score=score, risk=risk, reasons=reasons)

@app.route('/download-decrypted/<filename>')
@login_required
def download_decrypted(filename):
    return send_file(os.path.join(DECRYPTED_FOLDER, secure_filename(filename)), as_attachment=True)

@app.route('/download-encrypted/<filename>')
@login_required
def download_encrypted(filename):
    return send_file(os.path.join(ENCRYPTED_FOLDER, secure_filename(filename)), as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)