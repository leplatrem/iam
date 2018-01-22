#
# https://auth0.com/docs/quickstart/backend/python#add-api-authorization
# https://github.com/auth0-samples/auth0-python-api-samples/tree/master/00-Starter-Seed

import functools
import json
import os

from flask import Flask, request, jsonify, _app_ctx_stack
from flask_cors import cross_origin
import werkzeug

import doorman

DOORMAN_SERVER = os.getenv("DOORMAN_SERVER", "http://localhost:8080")
# This service is the Auth0 API id.
SERVICE = os.getenv("SERVICE", "SLocf7Sa1ibd5GNJMMqO539g7cKvWBOI")
HERE = os.path.abspath(os.path.dirname(__file__))
RECORDS_PATH = os.getenv("RECORDS_PATH", os.path.join(HERE, "records"))


app = Flask(__name__)

allowed = functools.partial(doorman.allowed, DOORMAN_SERVER, SERVICE)


@app.errorhandler(doorman.AuthZError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


def authorized(**allowed_kw):
    def wrapped(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            token = request.headers.get("Authorization", None)
            authz = allowed(token=token, **allowed_kw)
            _app_ctx_stack.top.authz = authz
            return f(*args, **kwargs)
        return wrapper
    return wrapped


@app.route("/")
@cross_origin(headers=["Content-Type", "Authorization"])
@cross_origin(headers=["Access-Control-Allow-Origin", "*"])
@authorized(resource="hello")
def hello():
    """A valid access token is required to access this route
    """
    authz = _app_ctx_stack.top.authz
    return jsonify(authz)


@app.route("/records")
@cross_origin(headers=["Content-Type", "Authorization"])
@cross_origin(headers=["Access-Control-Allow-Origin", "*"])
@authorized(resource="record", action="list")
def records():
    authz = _app_ctx_stack.top.authz
    main_principal = authz["principals"][0]
    records = Records.list(author=main_principal)
    return jsonify(records)


@app.route("/records/<name>", methods=('GET', 'PUT'))
@cross_origin(headers=["Content-Type", "Authorization"])
@cross_origin(headers=["Access-Control-Allow-Origin", "*"])
def record(name):
    token = request.headers.get("Authorization", None)

    record, author = Records.read(name)

    if request.method == "GET":
        action = "read"
    else:
        action = "create" if record is None else "update"

    # Check if allowed to perform action (will raise AuthZError if not authorized)
    authz = allowed(resource="record", action=action, token=token, context={"author": author})

    # Return 404 if allowed to read but unknown record.
    if record is None and request.method == "GET":
        raise werkzeug.exceptions.NotFound()

    # Save content on PUT
    if request.method == "PUT":
        body = request.data.decode("utf-8")
        main_principal = authz["principals"][0]
        record = Records.save(name, body, main_principal)

    return jsonify(record)


class Records:
    @staticmethod
    def list(author):
        all_records = [f for f in os.listdir(RECORDS_PATH) if f.endswith(".json")]
        all_contents = [(f, json.load(open(os.path.join(RECORDS_PATH, f)))) for f in all_records]
        return [{'name': f.replace('.json', ''), 'body': content['body']}
                for f, content in all_contents if content["author"] == author]

    @staticmethod
    def read(name):
        path = os.path.join(RECORDS_PATH, "{}.json".format(os.path.basename(name)))
        if os.path.exists(path):
            with open(path, 'r') as f:
                content = json.load(f)
                return content['body'], content['author']
        return None, None

    @staticmethod
    def save(name, body, author):
        path = os.path.join(RECORDS_PATH, "{}.json".format(os.path.basename(name)))
        body = {'body': body, 'author': author}
        with open(path, 'w') as f:
            json.dump(body, f)
        return body


if __name__ == "__main__":
    print("RECORDS_PATH", RECORDS_PATH)
    print("DOORMAN_SERVER", DOORMAN_SERVER)
    print("SERVICE", SERVICE)
    app.run(host="0.0.0.0", port=os.getenv("PORT", 8000))
