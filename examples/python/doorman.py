import json
import urllib


class AuthZError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


def allowed(doorman, service, *,
            resource=None, action=None, token=None, principals=None, context=None):
    doorman_url = doorman + "/allowed"
    payload = {
        "resource": resource,
        "action": action,
        "principals": principals,
        "context": context,
    }
    body = json_dumps_ignore_none(payload)
    headers = {
        "Authorization": token or '',
        "Origin": service,
    }
    r = urllib.request.Request(doorman_url, data=body.encode("utf-8"), headers=headers)
    try:
        resp = urllib.request.urlopen(r)
    except urllib.error.HTTPError as e:
        raise AuthZError(e.read().decode("utf-8"), e.code)

    response_body = json.loads(resp.read().decode("utf-8"))

    if not response_body["allowed"]:
        raise AuthZError(response_body, 403)

    return response_body


def json_dumps_ignore_none(d):
    return json.dumps({k: v for k, v in d.items() if v is not None})
