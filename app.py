from flask import Flask, render_template, request
import re
from urllib.parse import urlparse
import ipaddress
from cryptography.fernet import Fernet
import os 
from flask import Flask, render_template, request, send_file, abort

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
ENCRYPTED_FOLDER = os.path.join(BASE_DIR, "Encrypted")
DECRYPTED_FOLDER = os.path.join(BASE_DIR, "Decrypted")

app = Flask(__name__)

@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.form['url']
    score = 0
    reasons = []

    # Check HTTPS
    if not url.startswith("https"):
        score += 20
        reasons.append("URL does not use HTTPS.")

    # URL length
    if len(url) > 75:
        score += 15
        reasons.append("URL length is suspiciously long.")
    
    #check for IP address in URL
    try:
        ipaddress.ip_address(urlparse(url).netloc)
        score += 25
        reasons.append("URL contains an IP address instead of a domain name.")
    except ValueError:
        pass
    
    #suspicious TDL 
    suspicious_tlds = [".tk", ".ml", ".ga", ".cf"]
    for tld in suspicious_tlds:
        if url.lower().endswith(tld):
            score += 20
            reasons.append(f"URL uses suspicious TLD: {tld}")
            break

    # Suspicious symbols
    if "@" in url:
        score += 20
        reasons.append("URL contains '@' symbol.")

    if "-" in url:
        score += 10
        reasons.append("URL contains hyphen (-).")

    # Multiple subdomains
    domain = urlparse(url).netloc
    if domain.count(".") > 2:
        score += 15
        reasons.append("URL contains multiple subdomains.")

    # Suspicious keywords
    suspicious_keywords = ["login", "verify", "secure", "update", "bank"]
    for word in suspicious_keywords:
        if word in url.lower():
            score += 10
            reasons.append(f"URL contains suspicious keyword: {word}")
            break

    # Risk level
    if score <= 20:
        risk = "Low Risk"
    elif score <= 50:
        risk = "Medium Risk"
    else:
        risk = "High Risk"
    return render_template("result.html", url=url, score=score, risk=risk, reasons=reasons)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/encrypt')
def encryption():
    return render_template('encrypt.html')

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt_file():
    if request.method == 'POST':
        encrypted_file = request.files['file']
        key = request.form['key'].encode()

        if encrypted_file and key:
            encrypted_path = os.path.join("uploads", encrypted_file.filename)
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

            return render_template(
                "decrypt_result.html",
                filename=decrypted_filename
                ) 

    return render_template("decrypt.html")

@app.route('/phishing')
def phishing():
    return render_template('phishing.html')

@app.route('/encrypt', methods=['POST'])
def encrypt_file():
    file = request.files['file']

    if file:
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)

        # Save original file
        original_path = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(original_path)

        # Generate key
        key = Fernet.generate_key()
        cipher = Fernet(key)

        # Read original file
        with open(original_path, "rb") as f:
            file_data = f.read()

        # Encrypt
        encrypted_data = cipher.encrypt(file_data)

        encrypted_filename = file.filename + ".enc"
        encrypted_path = os.path.join(ENCRYPTED_FOLDER, encrypted_filename)

        with open(encrypted_path, "wb") as f:
            f.write(encrypted_data)

        return render_template(
            "encrypt_result.html",
            filename=encrypted_filename,
            key=key.decode())
        
    return "No file uploaded."

@app.route('/download-decrypted/<filename>')
def download_decrypted(filename):
    file_path = os.path.join(DECRYPTED_FOLDER, filename)
    return send_file(file_path, as_attachment=True)

@app.route('/download-encrypted/<filename>')
def download_encrypted(filename):
    file_path = os.path.join(ENCRYPTED_FOLDER, filename)
    print("Downloading:", file_path)
    return send_file(file_path, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)