from flask import Flask, render_template, request
import hashlib, socket, requests
import random
import string

app = Flask(__name__)

# Homepage
@app.route("/")
def home():
    return render_template("index.html")

# File Hash Scanner (Malware Checker)
@app.route("/check_hash", methods=["POST"])
def check_hash():
    uploaded_file = request.files["file"]
    if uploaded_file:
        file_content = uploaded_file.read()
        file_hash = hashlib.sha256(file_content).hexdigest()
        return f"SHA256 Hash: {file_hash}"
    return "No file uploaded!"

# Port Scanner
@app.route("/scan_port", methods=["POST"])
def scan_port():
    target = request.form["target"]
    port = int(request.form["port"])

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        result = s.connect_ex((target, port))
        if result == 0:
            return f"✅ Port {port} on {target} is OPEN"
        return f"❌ Port {port} on {target} is CLOSED"

# Password Strength Checker
@app.route("/check_password", methods=["POST"])
def check_password():
    password = request.form["password"]
    if len(password) < 8:
        return "❌ Weak: Password too short (must be 8+ characters)"
    if not any(char.isupper() for char in password):
        return "❌ Weak: No uppercase letter"
    if not any(char.isdigit() for char in password):
        return "❌ Weak: No number included"
    return "✅ Strong Password!"

# WHOIS & IP Lookup
@app.route("/lookup_ip", methods=["POST"])
def lookup_ip():
    ip_address = request.form["ip_address"]
    response = requests.get(f"https://ipinfo.io/{ip_address}/json")
    return response.json()

# Secure Password Generator
@app.route("/generate_password", methods=["POST"])
def generate_password():
    length = int(request.form.get("length", 12))  # Default length: 12
    use_upper = "upper" in request.form
    use_lower = "lower" in request.form
    use_numbers = "numbers" in request.form
    use_symbols = "symbols" in request.form

    char_set = ""
    if use_upper:
        char_set += string.ascii_uppercase
    if use_lower:
        char_set += string.ascii_lowercase
    if use_numbers:
        char_set += string.digits
    if use_symbols:
        char_set += string.punctuation

    if not char_set:
        return "❌ Error: Please select at least one character type."

    password = "".join(random.choice(char_set) for _ in range(length))
    return f"🔐 Generated Password: {password}"

# What's My IP Address
@app.route("/my_ip", methods=["GET"])
def my_ip():
    user_ip = request.remote_addr  # Get user's IP address
    return f"🌍 Your IP Address: {user_ip}"


if __name__ == "__main__":
    app.run(debug=True)
