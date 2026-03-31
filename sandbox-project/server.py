from flask import Flask, request, jsonify
from flask_cors import CORS
from sandbox_core import execute_safe, SecurityViolation
import logging
import os
import traceback

app = Flask(__name__, static_folder="static", static_url_path="")
CORS(app, resources={r"/*": {"origins": "*"}})

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    filename="logs/violations.log",
    level=logging.WARNING,
    format="%(asctime)s | %(message)s"
)

execution_stats = {
    "total": 0,
    "allowed": 0,
    "blocked": 0,
    "timeout": 0,
    "errors": 0
}

@app.route("/")
def index():
    return app.send_static_file("index.html")

@app.route("/execute", methods=["POST", "OPTIONS"])
def execute():
    if request.method == "OPTIONS":
        return jsonify({}), 200
    try:
        data = request.get_json(force=True, silent=True)
        if not data or "code" not in data:
            return jsonify({"status": "error", "message": "No code provided"}), 400

        code = data["code"].strip()
        execution_stats["total"] += 1

        if not code:
            return jsonify({"status": "error", "message": "Empty input"}), 400

        if len(code) > 5000:
            return jsonify({
                "status": "blocked",
                "violation": "INPUT_SIZE_LIMIT",
                "severity": "MEDIUM",
                "message": "Input exceeds 5000 character limit"
            }), 413

        try:
            result = execute_safe(code)
            execution_stats["allowed"] += 1
            if result["status"] == "timeout":
                execution_stats["timeout"] += 1
            elif result["status"] == "runtime_error":
                execution_stats["errors"] += 1
            return jsonify({
                "status": result["status"],
                "output": result["output"],
                "error": result["error"],
                "time_ms": result["time_ms"]
            })

        except SecurityViolation as e:
            execution_stats["blocked"] += 1
            logging.warning(
                f"VIOLATION | {e.severity} | {e.rule} | {e.detail} | INPUT: {code[:200]}"
            )
            return jsonify({
                "status": "blocked",
                "violation": e.rule,
                "severity": e.severity,
                "message": str(e.detail)
            }), 403

    except Exception as e:
        print("INTERNAL ERROR:", traceback.format_exc())
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route("/stats", methods=["GET"])
def stats():
    return jsonify(execution_stats)

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "running", "sandbox": "active"})

if __name__ == "__main__":
    print("Sandbox server starting on http://127.0.0.1:5000")
    app.run(debug=True, host="0.0.0.0", port=5000)

