
from flask import Flask, request, jsonify
from flask_restful import Api
import json
import eth_account
import algosdk
import pprint

app = Flask(__name__)
api = Api(app)
app.url_map.strict_slashes = False

@app.route('/verify', methods=['GET','POST'])
def verify():
    content = request.get_json(silent=True)

    if 'sig' not in content or 'payload' not in content:
           return {'status': 400,
                   'message': "Malformed data. No sig or payload",
            }

    sig = content["sig"]
    payload = content["payload"]

    missing_keys = [x for x in ["message", "pk", "platform"] if x not in payload.keys()]

    if len(missing_keys):
        return {'status': 400,
                   'message': "Malformed data. Missing payload keys",
            }

    if payload['platform'].lower() == "ethereum":
        verifier = verify_ethereum
    elif payload['platform'].lower() == "algorand":
        verifier = verify_algorand

    #Check if signature is valid
    print(sig, payload)
    result = verifier(sig, payload)  #Should only be true if signature validates
    return jsonify(result)

def verify_ethereum(sig, payload):
    jsonified_dict = json.dumps(payload)
    signable_message = eth_account.messages.encode_defunct(text=jsonified_dict)
    try:
        recovered_address = eth_account.Account.recover_message(signable_message=signable_message, signature=sig)
        print(recovered_address)
    except:
        return False
    if recovered_address == payload["pk"]:
        return True
    return False

def verify_algorand(sig, payload):
    jsonified_dict = json.dumps(payload)
    if algosdk.util.verify_bytes(payload["message"].encode('utf-8'), sig, payload):
        return True
    return False

if __name__ == '__main__':
    app.run(port='5002')
