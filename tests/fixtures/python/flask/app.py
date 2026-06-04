from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/")
def index():
    return "Hello, World!"


@app.route("/api/users", methods=["GET"])
def list_users():
    return jsonify([])


@app.route("/api/users", methods=["POST"])
def create_user():
    data = request.get_json()
    return jsonify(data), 201


@app.get("/api/health")
def health_check():
    return jsonify({"status": "ok"})


def _internal_helper():
    """Not a route, should be flagged as dead code."""
    pass


if __name__ == "__main__":
    app.run(debug=True)
