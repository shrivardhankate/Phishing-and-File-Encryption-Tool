from fileinput import filename
from flask import Flask, render_template, request, send_file, abort, redirect, url_for
import re
from urllib.parse import urlparse
import ipaddress
from cryptography.fernet import Fernet
import os 
from database import init_db
from database import get_db_connection
from werkzeug.utils import secure_filename 
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
ENCRYPTED_FOLDER = os.path.join(BASE_DIR, "Encrypted")
DECRYPTED_FOLDER = os.path.join(BASE_DIR, "Decrypted")

app = Flask(__name__)

init_db()

def log_file_action(user_id, filename, action):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO file_logs (user_id, file_name, action) VALUES (?, ?, ?)",
        (user_id, filename, action)
    )

    conn.commit()
    conn.close()

@app.route('/')
def home():
    return render_template('login.html')

from werkzeug.security import generate_password_hash, check_password_hash

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()

    if not username or not password:
        return render_template('login.html', error='Username and password are required.')

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        user = cursor.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if user:
            if check_password_hash(user['password_hash'], password):
                return redirect(url_for('home_page'))
            else:
                return render_template('login.html', error="Invalid password")

        else:
            hashed_password = generate_password_hash(password)

            cursor.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, hashed_password)
            )

            conn.commit()

            return redirect(url_for('home_page'))

    finally:
        conn.close()

@app.route('/home')
def home_page():
    return render_template('index.html')

@app.route('/encrypt')
def encryption():
    return render_template('encrypt.html')

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

@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.form['url']
    score = 0
    reasons = []

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
        risk = "Low Risk"
    elif score <= 50:
        risk = "Medium Risk"
    else:
        risk = "High Risk"
    #Store phishing analysis in database
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
def decrypt_file():
    if request.method == 'POST':
        encrypted_file = request.files['file']
        key = request.form['key'].encode()

        if encrypted_file and key:
            filename = secure_filename(encrypted_file.filename)
            encrypted_path = os.path.join("uploads", filename)            
            encrypted_file.save(encrypted_path)
            os.makedirs(DECRYPTED_FOLDER, exist_ok=True)

            cipher = Fernet(key)

            with open(encrypted_path, "rb") as f:
                encrypted_data = f.read()

            try:
                decrypted_data = cipher.decrypt(encrypted_data)
            except:
                return "Invalid Key or Corrupted File"

            decrypted_filename = encrypted_file.filename.replace(".enc", "")
            decrypted_path = os.path.join(DECRYPTED_FOLDER, decrypted_filename)

            with open(decrypted_path, "wb") as f:
                f.write(decrypted_data)
            
            log_file_action(1, decrypted_filename, "decrypt")

            return render_template(
                "decrypt_result.html",
                filename=decrypted_filename
                ) 

    return render_template("decrypt.html")

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt_file():
    if request.method == 'POST':
        file = request.files['file']

        if file:
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

            log_file_action(1, file.filename, "encrypt")

            return render_template(
                "encrypt_result.html",
                filename=encrypted_filename,
                key=key.decode()
            )

    return render_template('encrypt.html')

@app.route('/logs')
def view_logs():
    conn = get_db_connection()
    logs = conn.execute("SELECT * FROM file_logs").fetchall()
    conn.close()

    return str([dict(log) for log in logs])

if __name__ == '__main__':
    app.run(debug=True)