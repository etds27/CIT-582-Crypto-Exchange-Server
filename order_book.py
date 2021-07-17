from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime

from models import Base, Order

engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

required_fields = ['sender_pk', 'receiver_pk', 'buy_currency', 'sell_currency', 'buy_amount', 'sell_amount']


def process_order(order):
    for field in order.keys():
        if field not in required_fields:
            return False

    order_obj = insert_order(order)
    find_existing_matching_order(order_obj)


def insert_order(order):
    order_obj = Order(sender_pk=order['sender_pk'],
                      receiver_pk=order['receiver_pk'],
                      buy_currency=order['buy_currency'],
                      sell_currency=order['sell_currency'],
                      buy_amount=order['buy_amount'],
                      sell_amount=order['sell_amount'])

    session.add(order_obj)
    session.commit()
    return order_obj


def find_existing_matching_order(order):
    query = text("SELECT * from orders")
    orders = session.execute(query)

    for existing_order in orders:
        print(existing_order)
