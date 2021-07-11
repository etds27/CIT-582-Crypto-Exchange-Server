
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

    if content['platform'] == "ethereum":
        verifier = verify_ethereum
    elif content['platform'] == "algorand":
        verifier = verify_algorand
    pprint.pprint(content)

    #Check if signature is valid
    result = verifier(content['sig'], content['payload'])  #Should only be true if signature validates
    return jsonify(result)

def verify_ethereum(sig, payload):
    signable_message = eth_account.messages.encode_defunct(text=payload["message"])
    recovered_address == eth_account.Account.recover_message(signable_message, sig)

    if recovered_address == payload["pk"]:
        return True
    return False

def verify_algorand(sig, payload):
    if algosdk.util.verify_bytes(payload["message"].encode('utf-8'), sig, payload["pk"]):
        return True
    return False

if __name__ == '__main__':
    app.run(port='5002')
