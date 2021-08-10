import web3.exceptions
from algosdk import mnemonic
from eth_account import Account
from flask import Flask, request, g
# from flask_restful import Resource, Api
from sqlalchemy import create_engine, text
from flask import jsonify
import json
import eth_account
import algosdk
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import load_only
from datetime import datetime
import math
import sys
import traceback

from web3 import Web3
from web3.auto import w3

import send_tokens
from models import Order, Base, Log, TX

engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

app = Flask(__name__)

Account.enable_unaudited_hdwallet_features()
acct, eth_mnemonic_secret = Account.create_with_mnemonic()
algo_mnemonic_secret = "upper learn noodle occur rely soon shallow gossip ring orange sadness enhance gather tattoo pigeon gorilla ladder leader drive luggage cake fabric main abstract dress"


@app.before_request
def create_session():
    g.session = scoped_session(DBSession)


@app.teardown_appcontext
def shutdown_session(response_or_exc):
    sys.stdout.flush()
    g.session.commit()
    g.session.remove()


from send_tokens import connect_to_algo, connect_to_eth, send_tokens_algo, send_tokens_eth

""" Suggested helper methods """


def connect_to_blockchains():
    try:
        # If g.acl has not been defined yet, then trying to query it fails
        acl_flag = False
        g.acl
    except AttributeError as ae:
        acl_flag = True

    try:
        if acl_flag or not g.acl.status():
            # Define Algorand client for the application
            g.acl = connect_to_algo()
    except Exception as e:
        print("Trying to connect to algorand client again")
        print(traceback.format_exc())
        g.acl = connect_to_algo()

    try:
        icl_flag = False
        g.icl
    except AttributeError as ae:
        icl_flag = True

    try:
        if icl_flag or not g.icl.health():
            # Define the index client
            g.icl = connect_to_algo(connection_type='indexer')
    except Exception as e:
        print("Trying to connect to algorand indexer client again")
        print(traceback.format_exc())
        g.icl = connect_to_algo(connection_type='indexer')

    try:
        w3_flag = False
        g.w3
    except AttributeError as ae:
        w3_flag = True

    try:
        if w3_flag or not g.w3.isConnected():
            g.w3 = connect_to_eth()
    except Exception as e:
        print("Trying to connect to web3 again")
        print(traceback.format_exc())
        g.w3 = connect_to_eth()


def get_algo_keys(mnemonic_secret):
    # TODO: Generate or read (using the mnemonic secret)
    # the algorand public/private keys
    algo_sk = mnemonic.to_private_key(mnemonic_secret)
    algo_pk = mnemonic.to_public_key(mnemonic_secret)
    return algo_sk, algo_pk


def get_eth_keys(mnemonic_secret):
    # TODO: Generate or read (using the mnemonic secret)
    # the ethereum public/private keys
    acct = w3.eth.account.from_mnemonic(mnemonic_secret)
    eth_pk = acct._address
    eth_sk = acct._private_key
    return eth_sk, eth_pk


def execute_txes(txes):
    if txes is None:
        return True
    if len(txes) == 0:
        return True
    print(f"Trying to execute {len(txes)} transactions")
    print(f"IDs = {[tx['order_id'] for tx in txes]}")
    eth_sk, eth_pk = get_eth_keys(eth_mnemonic_secret)
    algo_sk, algo_pk = get_algo_keys(algo_mnemonic_secret)

    if not all(tx['platform'] in ["Algorand", "Ethereum"] for tx in txes):
        print("Error: execute_txes got an invalid platform!")
        print(tx['platform'] for tx in txes)

    algo_txes = [tx for tx in txes if tx['platform'] == "Algorand"]
    eth_txes = [tx for tx in txes if tx['platform'] == "Ethereum"]

    # TODO:
    #       1. Send tokens on the Algorand and eth testnets, appropriately
    #          We've provided the send_tokens_algo and send_tokens_eth skeleton methods in send_tokens.py
    #       2. Add all transactions to the TX table
    send_tokens_eth(g.w3, eth_sk, eth_txes)
    send_tokens_algo(g.acl, algo_sk, algo_txes)


def log_message(d):
    log = Log(message=json.dumps(d))
    g.session.add(log)
    g.session.commit()


def verify_ethereum_transaction(order, tx_id):
    _, exchange_pk = get_eth_keys(eth_mnemonic_secret)
    try:
        tx = g.w3.eth.get_transaction(tx_id)
        if not (
                tx['value'] == order['sell_amount'] and
                tx['from'] == order['sender_pk'] and
                tx['to'] == exchange_pk
        ):
            print("Unable to verify ethereum transaction: %s == %s, %s == %s, %s == %s" % (
                tx['from'], order['sender_pk'], tx['value'], order['sell_amount'], tx['to'],
                exchange_pk))
            return False

    except web3.exceptions.TransactionNotFound:
        print("ETH Transaction not found")
        return False

    return True


def verify_algorand_transaction(order, tx_id):
    print("attempting to verify algorand transaction")
    _, exchange_pk = get_algo_keys(algo_mnemonic_secret)
    print("Getting exchange account: %s" % str(exchange_pk))
    print("Connected to indexer")
    tx = g.icl.search_transactions(txid=tx_id)
    print("Searched with indexer")
    # If txid doesnt exist
    if len(tx) == 0:
        print("Transaction ID %s doesnt exist" % str(tx_id))
        return False
    tx_dict = tx

    if not (
            tx_dict['sender'] == order['sender_pk'] and
            tx_dict['amt'] == order['sell_amount'] and
            tx_dict['receiver'] == exchange_pk
    ):
        print("Unable to verify algorand transaction: %s == %s, %s == %s, %s == %s" % (
            tx_dict['sender'], order['sender_pk'], tx_dict['amt'], order['sell_amount'], tx_dict['receiver'],
            exchange_pk))
        return False
    return True


def verify_ethereum(sig, payload):
    jsonified_dict = json.dumps(payload)
    signable_message = eth_account.messages.encode_defunct(text=jsonified_dict)
    try:
        recovered_address = eth_account.Account.recover_message(signable_message=signable_message, signature=sig)
    except:
        print("Unable to recover ethereum address: %s" % str(payload))
        return False
    if recovered_address == payload["sender_pk"]:
        return True
    print("Addresses do not match: %s != %s | %s" % (recovered_address, payload["sender_pk"], str(payload)))
    return False


def verify_algorand(sig, payload):
    jsonified_dict = json.dumps(payload)
    if algosdk.util.verify_bytes(jsonified_dict.encode('utf-8'), sig, payload["sender_pk"]):
        return True
    print("Unable to verify algorand signature: %s" % str(payload))
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

    orders = [order_obj.id]

    child_id = process_matching_orders(order_obj, matching_orders)
    if not child_id == order_obj.id:
        orders.append(child_id)

    # headers = ["id", "buy_currency", "sell_currency", "buy_amount", "sell_amount", "counterparty_id",
    #           "creator_id, filled"]
    # orders = g.session.execute("SELECT %s from orders" % ",".join(headers))

    return orders


def process_matching_orders(order, matching_orders):
    print("Processing matching orders for: %s" % str(order.id))
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
            print("result.sell_amount > order.buy_amount")
            new_sell_amt = result.sell_amount - order.buy_amount
            ratio = result.sell_amount / float(result.buy_amount)
            new_buy_amt = new_sell_amt // ratio
            new_order = dict(buy_currency=result.buy_currency, sell_currency=result.sell_currency,
                             buy_amount=new_buy_amt, sell_amount=new_sell_amt, sender_pk=result.sender_pk,
                             receiver_pk=result.receiver_pk, creator_id=result.id)
            txes = [dict(order_id=order.id,
                         receiver_pk=order.receiver_pk,
                         amount=order.buy_amount,
                         platform=order.buy_currency),
                    dict(order_id=result.id,
                         receiver_pk=result.receiver_pk,
                         amount=order.sell_amount,
                         platform=order.sell_currency)]
            execute_txes(txes)
            child_id = process_order(new_order)

        # If the buyer is attempting to buy more than the seller is offering, create a new order on behalf of buyer
        elif result.sell_amount < order.buy_amount:
            print("result.sell_amount < order.buy_amount")
            new_buy_amt = order.buy_amount - result.sell_amount
            ratio = order.buy_amount / float(order.sell_amount)
            new_sell_amount = new_buy_amt // ratio + (new_buy_amt % ratio > 0)
            new_order = dict(buy_currency=order.buy_currency, sell_currency=order.sell_currency,
                             buy_amount=new_buy_amt, sell_amount=new_sell_amount, sender_pk=order.sender_pk,
                             receiver_pk=order.receiver_pk, creator_id=order.id)
            txes = [dict(order_id=order.id,
                         receiver_pk=order.receiver_pk,
                         amount=result.sell_amount,
                         platform=order.buy_currency),
                    dict(order_id=result.id,
                         receiver_pk=result.receiver_pk,
                         amount=result.buy_amount,
                         platform=order.sell_currency)]
            execute_txes(txes)
            child_id = process_order(new_order)
        else:
            print("result.sell_amount == order.buy_amount")
            txes = [dict(order_id=order.id,
                         receiver_pk=order.receiver_pk,
                         amount=result.sell_amount,
                         platform=order.buy_currency),
                    dict(order_id=result.id,
                         receiver_pk=result.receiver_pk,
                         amount=result.buy_amount,
                         platform=order.sell_currency)]
            execute_txes(txes)
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

    tx_dict = dict(
        platform=order_obj.sell_currency,
        receiver_pk=order_obj.receiver_pk,
        order_id=order_obj.id,
        tx_id=order_obj.tx_id
    )

    tx = TX(**tx_dict)

    g.session.add(order_obj)
    g.session.add(tx)
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


@app.route('/address', methods=['POST'])
def address():
    if request.method == "POST":
        content = request.get_json(silent=True)
        if 'platform' not in content.keys():
            print(f"Error: no platform provided")
            return jsonify("Error: no platform provided")
        if not content['platform'] in ["Ethereum", "Algorand"]:
            print(f"Error: {content['platform']} is an invalid platform")
            return jsonify(f"Error: invalid platform provided: {content['platform']}")

        if content['platform'].lower() == "ethereum":
            eth_sk, eth_pk = get_eth_keys(eth_mnemonic_secret)
            return jsonify(eth_pk)
        if content['platform'].lower() == "algorand":
            algo_sk, algo_pk = get_algo_keys(algo_mnemonic_secret)
            return jsonify(algo_pk)


@app.route('/trade', methods=['POST'])
def trade():
    if request.method == "POST":
        print()
        content = request.get_json(silent=True)
        print(f"content = {json.dumps(content)}")
        columns = ["sender_pk", "receiver_pk", "buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform",
                   "tx_id"]
        fields = ["sig", "payload"]
        error = False
        connect_to_blockchains()
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
            log_message("Verified signature %s" % payload["tx_id"])
            print("Verified signature %s" % payload["tx_id"])
            d = dict(sender_pk=payload["sender_pk"], receiver_pk=payload["receiver_pk"],
                     buy_currency=payload["buy_currency"], sell_currency=payload["sell_currency"],
                     buy_amount=payload["buy_amount"], sell_amount=payload["sell_amount"],
                     signature=sig, tx_id=payload["tx_id"])

            valid_transaction = False
            print("Created order dict %s" % str(d))
            if payload["sell_currency"].lower() == "ethereum":
                valid_transaction = verify_ethereum_transaction(d, tx_id=d["tx_id"])
            elif payload["sell_currency"].lower() == "algorand":
                valid_transaction = verify_algorand_transaction(d, tx_id=d["tx_id"])

            if valid_transaction:
                log_message("Verified transaction %s" % d["tx_id"])
                print("Verified transaction %s" % d["tx_id"])

                order_ids = process_order(d)

            else:
                print("Transaction unable to be verified")
                log_message(payload)
                return jsonify(False)
        else:
            log_message(payload)
            return jsonify(False)
        # TODO: Be sure to return jsonify(True) or jsonify(False) depending on if the method was successful

        return jsonify(True)


@app.route('/order_book')
def order_book():
    result = dict(data=[])
    result_keys = ["sender_pk", "receiver_pk", "buy_currency", "sell_currency", "buy_amount", "sell_amount",
                   "signature", "tx_id"]
    statement = "SELECT %s FROM orders" % ",".join(result_keys)
    orders = g.session.execute(statement)

    # Add orders to data list sequentially
    for order in orders:
        result["data"].append({k: order[k] for k in result_keys})

    # Note that you can access the database session using g.session
    return jsonify(result)


if __name__ == '__main__':
    app.run(port='5002')
