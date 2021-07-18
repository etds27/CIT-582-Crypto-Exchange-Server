from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import pprint
from models import Base, Order

engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

required_fields = ['sender_pk', 'receiver_pk', 'buy_currency', 'sell_currency', 'buy_amount', 'sell_amount']


def find_column_id_by_name(key, query=None):
    return get_columns(query).index(key)


def get_columns(query=None):
    if query is None:
        query = text("SELECT * FROM orders")
    return list(session.execute(query).keys())


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
    # print(headers)
    orders = session.execute("SELECT %s from orders" % ",".join(headers))
    # for order in sorted(orders, key=lambda x: x.sell_amount / x.buy_amount, reverse=False):
    # for order in orders:
    #    print(order)

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
        result = session.query(Order).filter(Order.id == result_id).first()

        # Fill current order's and result order with counterparty and time info
        tx_time = datetime.now()
        result.filled = tx_time
        order.filled = tx_time
        result.counterparty_id = order.id
        order.counterparty_id = result.id
        """
        print("Order filled: %s" % tx_time)
        print("Order buy currency: %s " % order.buy_currency)
        print("Order sell currency: %s " % order.sell_currency)
        print("Order buy amount: %s " % order.buy_amount)
        print("Order sell amount: %s " % order.sell_amount)
        print()
        print("Old Order buy currency: %s " % result.buy_currency)
        print("Old Order sell currency: %s " % result.sell_currency)
        print("Old Order buy amount: %s " % result.buy_amount)
        print("Old Order sell amount: %s " % result.sell_amount)
        print()
        """

        # If the seller is selling more than the buyer, create a new sell order on behalf of the seller
        if result.sell_amount > order.buy_amount:
            new_sell_amt = result.sell_amount - order.buy_amount
            ratio = result.sell_amount / float(result.buy_amount)
            new_buy_amt = new_sell_amt // ratio
            new_order = dict(buy_currency=result.buy_currency, sell_currency=result.sell_currency,
                             buy_amount=new_buy_amt, sell_amount=new_sell_amt, sender_pk=result.sender_pk,
                             receiver_pk=result.receiver_pk, creator_id=result.id)
            child_id = process_order(new_order)
            """
            print("Child order id: %s" % child_id)
            print("Child order buy currency: %s" % new_order["buy_currency"])
            print("Child order sell currency: %s" % new_order["sell_currency"])
            print("Child order buy amount: %s" % new_order["buy_amount"])
            print("Child order sell amount: %s" % new_order["sell_amount"])
            """

        # If the buyer is attempting to buy more than the seller is offering, create a new order on behalf of buyer
        elif result.sell_amount < order.buy_amount:
            new_buy_amt = order.buy_amount - result.sell_amount
            ratio = order.buy_amount / float(order.sell_amount)
            new_sell_amount = new_buy_amt // ratio + (new_buy_amt % ratio > 0)
            new_order = dict(buy_currency=order.buy_currency, sell_currency=order.sell_currency,
                             buy_amount=new_buy_amt, sell_amount=new_sell_amount, sender_pk=order.sender_pk,
                             receiver_pk=order.receiver_pk, creator_id=order.id)
            child_id = process_order(new_order)
            """
            print("Child order id: %s" % child_id)
            print("Child order buy currency: %s" % new_order["buy_currency"])
            print("Child order sell currency: %s" % new_order["sell_currency"])
            print("Child order buy amount: %s" % new_order["buy_amount"])
            print("Child order sell amount: %s" % new_order["sell_amount"])
            """

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
    session.add(order_obj)
    session.flush()
    session.commit()

    return order_obj


def create_child_order(order, matching_order):
    pass


def find_existing_matching_orders(order):
    exchange_ratio = order.buy_amount / order.sell_amount
    query = text("SELECT * FROM orders WHERE filled is NULL AND buy_currency == '%s' AND sell_currency == '%s' AND "
                 "CAST(sell_amount AS DECIMAL) / buy_amount >= %f" % (
                     order.sell_currency, order.buy_currency, exchange_ratio))
    # print(query)
    orders = session.execute(query)

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
