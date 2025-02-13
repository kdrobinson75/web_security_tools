from flask import Flask, render_template, request, jsonify
import hashlib, random, string, socket, requests

app = Flask(__name__)

# Homepage
@app.route("/")
def home():
    return render_template("index.html")

# ✅ Secure Password Generator
@app.route("/generate_password", methods=["POST"])
def generate_password():
    try:
        length = int(request.form.get("length", 12))  # Default to 12 if no length provided
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
            return jsonify({"error": "❌ Please select at least one character type."})

        password = "".join(random.choice(char_set) for _ in range(length))
        return jsonify({"password": password})

    except Exception as e:
        return jsonify({"error": f"⚠️ Error generating password: {str(e)}"})

# ✅ What's My IP Address
@app.route("/my_ip", methods=["GET"])
def my_ip():
    user_ip = request.remote_addr
    return jsonify({"ip": user_ip})

# ✅ Port Scanner
@app.route("/scan_port", methods=["POST"])
def scan_port():
    target = request.form["target"]
    port = int(request.form["port"])
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        result = s.connect_ex((target, port))
        status = "OPEN" if result == 0 else "CLOSED"
    
    return jsonify({"target": target, "port": port, "status": status})

# ✅ File Hash Scanner
@app.route("/check_hash", methods=["POST"])
def check_hash():
    uploaded_file = request.files["file"]
    if uploaded_file:
        file_content = uploaded_file.read()
        file_hash = hashlib.sha256(file_content).hexdigest()
        return jsonify({"file_hash": file_hash})
    return jsonify({"error": "No file uploaded!"})

# ✅ WHOIS & IP Lookup
@app.route("/lookup_ip", methods=["POST"])
def lookup_ip():
    ip_address = request.form["ip_address"]
    response = requests.get(f"https://ipinfo.io/{ip_address}/json")
    return jsonify(response.json())

if __name__ == "__main__":
    app.run(debug=True)
