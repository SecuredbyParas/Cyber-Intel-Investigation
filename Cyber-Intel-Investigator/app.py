from flask import Flask, render_template, jsonify

from modules.log_analysis import log_bp
from modules.network_scan import scan_bp
from modules.packet_analysis import packet_bp
from modules.threat_intel import threat_bp
from modules.live_capture import live_bp

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024   # upload limit = 50 MB

# connect every module to the app
app.register_blueprint(log_bp)
app.register_blueprint(scan_bp)
app.register_blueprint(packet_bp)
app.register_blueprint(threat_bp)
app.register_blueprint(live_bp)


@app.errorhandler(413)
def file_too_big(error):
    return jsonify({"error": "The file is too big (maximum 50 MB)."}), 413


@app.route("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    print("Cyber Intel Investigator running at http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000)
