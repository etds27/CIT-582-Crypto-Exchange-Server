from flask import Flask, request, g
from flask_restful import Resource, Api
from sqlalchemy import create_engine, select, MetaData, Table
from flask import jsonify
import json
import eth_account
import algosdk
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import load_only
import pprint
from models import Base, Order, Log

engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

app = Flask(__name__)


# These decorators allow you to use g.session to access the database inside the request code
@app.before_request
def create_session():
    g.session = scoped_session(
        DBSession)  # g is an "application global" https://flask.palletsprojects.com/en/1.1.x/api/#application-globals


@app.teardown_appcontext
def shutdown_session(response_or_exc):
    g.session.commit()
    g.session.remove()


"""
-------- Helper methods (feel free to add your own!) -------
"""


def log_message(d):
    log = Log(message=json.dumps(d))
    g.session.add(log)
    g.session.commit()


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
    if algosdk.util.verify_bytes(jsonified_dict.encode('utf-8'), sig, payload["pk"]):
        return True
    return False


def verify(sig, payload):
    """
    Verifies signature using platform given in payload

    :param sig: signature of the payload.
    :param payload: payload of items that were signed
    :return: True if signature is valid. False otherwise
    """
    verifier = None
    if payload['platform'].lower() == "ethereum":
        verifier = verify_ethereum
    elif payload['platform'].lower() == "algorand":
        verifier = verify_algorand

    # Check if signature is valid
    return verifier(sig, payload)  # Should only be true if signature validates


"""
---------------- Endpoints ----------------
"""


@app.route('/trade', methods=['POST'])
def trade():
    if request.method == "POST":
        content = request.get_json(silent=True)
        print(f"content = {json.dumps(content)}")
        columns = ["sender_pk", "receiver_pk", "buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform"]
        fields = ["sig", "payload"]
        error = False
        for field in fields:
            if not field in content.keys():
                print(f"{field} not received by Trade")
                print(json.dumps(content))
                log_message(content)
                return jsonify(False)

        error = False
        for column in columns:
            if column not in content['payload'].keys():
                print(f"{column} not received by Trade")
                error = True
        if error:
            print(json.dumps(content))
            log_message(content)
            return jsonify(False)

        sig = content["sig"]
        payload = content["payload"]

        if verify(sig, payload):
            order_obj = Order(sender_pk=payload["sender_pk"], receiver_pk=content["receiver_pk"],
                              buy_currency=payload["buy_currency"], sell_currency=content["sell_currency"],
                              buy_amount=payload["buy_amount"], sell_amount=payload["sell_amount"],
                              signature=sig)
            g.session.add(order_obj)
            g.session.commit()
        else:
            log_message(payload)

        # Your code here
        # Note that you can access the database session using g.session


@app.route('/order_book', methods=['GET', 'POST'])
def order_book():
    result = dict(data=[])
    result_keys = ["sender_pk", "receiver_pk", "buy_currency", "sell_currency", "buy_amount", "sell_amount",
                   "signature"]
    statement = "SELECT %s FROM orders" % ",".join(result_keys)
    orders = g.session.execute(statement)

    # Add orders to data list sequentially
    for order in orders:
        result["data"].append({k: order[k] for k in result_keys})

    # Note that you can access the database session using g.session
    return jsonify(result)


if __name__ == '__main__':
    app.run(port='5002')
