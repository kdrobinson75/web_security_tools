from flask import Flask, render_template, request
import hashlib
import hashlib, socket

app = Flask(__name__)

# Homepage
@app.route("/")
def home():
    return render_template("index.html")

# Route to check file hash (Malware Hash Checker)
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
    
    
if __name__ == "__main__":
    app.run(debug=True)
