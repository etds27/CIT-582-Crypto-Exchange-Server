from flask import Flask, request, g
from flask_restful import Resource, Api
from sqlalchemy import create_engine, text
from flask import jsonify
import json
import eth_account
import algosdk
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import load_only
from datetime import datetime
import sys

from models import Base, Order, Log

engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

app = Flask(__name__)


@app.before_request
def create_session():
    g.session = scoped_session(DBSession)


@app.teardown_appcontext
def shutdown_session(response_or_exc):
    sys.stdout.flush()
    g.session.commit()
    g.session.remove()


""" Suggested helper methods """


def fill_order(order, txes=[]):
    pass


def log_message(d):
    log = Log(message=json.dumps(d))
    g.session.add(log)
    g.session.commit()


def verify_ethereum(sig, payload):
    jsonified_dict = json.dumps(payload)
    signable_message = eth_account.messages.encode_defunct(text=jsonified_dict)
    try:
        recovered_address = eth_account.Account.recover_message(signable_message=signable_message, signature=sig)
    except:
        return False
    if recovered_address == payload["sender_pk"]:
        return True
    return False


def verify_algorand(sig, payload):
    jsonified_dict = json.dumps(payload)
    if algosdk.util.verify_bytes(jsonified_dict.encode('utf-8'), sig, payload["sender_pk"]):
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


required_fields = ['sender_pk', 'receiver_pk', 'buy_currency', 'sell_currency', 'buy_amount', 'sell_amount']


def find_column_id_by_name(key, query=None):
    return get_columns(query).index(key)


def get_columns(query=None):
    if query is None:
        query = text("SELECT * FROM orders")
    return list(g.session.execute(query).keys())


def process_order(order):
    for field in required_fields:
        if field not in order.keys():
            return False

    if order["buy_amount"] == 0 or order["sell_amount"] == 0:
        return False

    order_obj = insert_order(order)

    matching_orders = find_existing_matching_orders(order_obj)
    child_id = process_matching_orders(order_obj, matching_orders)

    headers = ["id", "buy_currency", "sell_currency", "buy_amount", "sell_amount", "counterparty_id",
               "creator_id, filled"]
    orders = g.session.execute("SELECT %s from orders" % ",".join(headers))

    return order_obj.id


def process_matching_orders(order, matching_orders):
    # Sort the matching orders by exchange rate that benefits the buyer
    sorted_exchange = sorted(matching_orders, key=lambda x: x.sell_amount / x.buy_amount, reverse=False)
    child_id = order.id

    # Only complete order if matching orders were found
    if len(sorted_exchange) > 0:
        i = 0
        # Take the best exhange ratio order
        id_idx = find_column_id_by_name("id")
        result_id = sorted_exchange[0][id_idx]
        result = g.session.query(Order).filter(Order.id == result_id).first()

        # Fill current order's and result order with counterparty and time info
        tx_time = datetime.now()
        result.filled = tx_time
        order.filled = tx_time
        result.counterparty_id = order.id
        order.counterparty_id = result.id

        # If the seller is selling more than the buyer, create a new sell order on behalf of the seller
        if result.sell_amount > order.buy_amount:
            new_sell_amt = result.sell_amount - order.buy_amount
            ratio = result.sell_amount / float(result.buy_amount)
            new_buy_amt = new_sell_amt // ratio
            new_order = dict(buy_currency=result.buy_currency, sell_currency=result.sell_currency,
                             buy_amount=new_buy_amt, sell_amount=new_sell_amt, sender_pk=result.sender_pk,
                             receiver_pk=result.receiver_pk, creator_id=result.id)
            child_id = process_order(new_order)

        # If the buyer is attempting to buy more than the seller is offering, create a new order on behalf of buyer
        elif result.sell_amount < order.buy_amount:
            new_buy_amt = order.buy_amount - result.sell_amount
            ratio = order.buy_amount / float(order.sell_amount)
            new_sell_amount = new_buy_amt // ratio + (new_buy_amt % ratio > 0)
            new_order = dict(buy_currency=order.buy_currency, sell_currency=order.sell_currency,
                             buy_amount=new_buy_amt, sell_amount=new_sell_amount, sender_pk=order.sender_pk,
                             receiver_pk=order.receiver_pk, creator_id=order.id)
            child_id = process_order(new_order)

    # print()
    # print()
    return child_id


def insert_order(order):
    """order_obj = Order(sender_pk=order['sender_pk'],
                      receiver_pk=order['receiver_pk'],
                      buy_currency=order['buy_currency'],
                      sell_currency=order['sell_currency'],
                      buy_amount=order['buy_amount'],
                        sell_amount=order['sell_amount'])"""
    order_obj = Order(**order)
    g.session.add(order_obj)
    g.session.flush()
    g.session.commit()

    return order_obj


def find_existing_matching_orders(order):
    exchange_ratio = order.buy_amount / order.sell_amount
    query = text("SELECT * FROM orders WHERE filled is NULL AND buy_currency == '%s' AND sell_currency == '%s' AND "
                 "CAST(sell_amount AS DECIMAL) / buy_amount >= %f" % (
                     order.sell_currency, order.buy_currency, exchange_ratio))
    # print(query)
    orders = g.session.execute(query)

    matching_orders = []
    for existing_order in orders:
        # Requirement new order buy matches previous order sell and new order sell matches previous order buy
        if not (existing_order.buy_currency == order.sell_currency and
                existing_order.sell_currency == order.buy_currency):
            continue

        # Exchange rate of buy order is at least that of sell order
        if not existing_order.sell_amount / existing_order.buy_amount >= order.buy_amount / order.sell_amount:
            continue

        matching_orders.append(existing_order)

    return matching_orders


""" End of helper methods """


@app.route('/trade', methods=['POST'])
def trade():
    if request.method == "POST":
        content = request.get_json(silent=True)
        print(f"content = {json.dumps(content)}")
        columns = ["sender_pk", "receiver_pk", "buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform"]
        fields = ["sig", "payload"]
        error = False
        for field in fields:
            if field not in content.keys():
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
            d = dict(sender_pk=payload["sender_pk"], receiver_pk=payload["receiver_pk"],
                     buy_currency=payload["buy_currency"], sell_currency=payload["sell_currency"],
                     buy_amount=payload["buy_amount"], sell_amount=payload["sell_amount"],
                     signature=sig)

            process_order(d)
        else:
            log_message(payload)
            return jsonify(False)
        # TODO: Fill the order
        # TODO: Be sure to return jsonify(True) or jsonify(False) depending on if the method was successful

        return jsonify(True)


@app.route('/order_book')
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
