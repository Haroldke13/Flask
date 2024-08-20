"""
PayPal API client for creating orders and capturing payments
"""

import requests
import json
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect()


def get_access_token(username, password):
    """
    Get an access token for PayPal API authentication

    Args:
        username (str): PayPal API username
        password (str): PayPal API password

    Returns:
        str: Access token

    Example:
        >>> username = 'AdZ38dWwRg-vOQxAjv_ZAXDRp2K6xhm2w55BwnBVW8wH9jHKZKC3BYosJqqOZ1m0cs4z9U5yHc-IxefZ'
        >>> password = 'EH3ywSuqZTBoUQP9HEEOTGH7UfjPR2eGs3eVWcl1qeb3bw1q_6Cs1RDPyd-Kfl4pB0gdswzR3iFFL2UD'
        >>> access_token = get_access_token(username, password)
        >>> print(access_token)
    """
    url = 'https://api-m.sandbox.paypal.com/v1/oauth2/Token'
    data = {'grant_type': 'client_credentials'}
    response = requests.post(url, data=data, auth=(username, password))
    if response.status_code == 200:
        return json.loads(response.text)['access_token']
    else:
        raise Exception('Error getting access token: {}'.format(response.text))

def create_order(access_token, data_orders):
    """
    Create a new order on PayPal

    Args:
        access_token (str): PayPal API access token
        data_orders (dict): Order data

    Returns:
        str: Order ID

    Example:
        >>> access_token = get_access_token(username, password)
        >>> data_orders = {
        ...     'intent': 'CAPTURE',
        ...     'purchase_units': [
        ...         {
        ...             'items': [
        ...                 {
        ...                     'name': 'Neura Credits',
        ...                     'description': 'carbon footprint levy',
        ...                     'quantity': '1',
        ...                     'unit_amount': {
        ...                         'currency_code': 'USD',
        ...                         'value': '5.00'
        ...                     }
        ...                 }
        ...             ],
        ...             'amount': [
        ...                 'currency_code': 'USD',
        ...                 'value': '5.00',
        ...                 'breakdown': {
        ...                     'item_total': {
        ...                         'currency_code': 'USD',
        ...                         'value': '5.00'
        ...                     }
        ...                 }
        ...             ]
        ...         }
        ...     ],
        ...     'application_context': {
        ...         'return_url': 'https://www.neuralflow.com.br/',
        ...         'cancel_url': 'https://www.neuralflow.com.br/'
        ...     }
        ... }
        >>> order_id = create_order(access_token, data_orders)
        >>> print(order_id)
    """
    url_orders = 'https://api-m.sandbox.paypal.com/v1/checkout/orders'
    response_orders = requests.post(url_orders, json=data_orders, headers={'Authorization': 'Bearer {}'.format(access_token)})
    if response_orders.status_code == 201:
        return json.loads(response_orders.text)['id']
    else:
        raise Exception('Error creating order: {}'.format(response_orders.text))

def capture_payment(access_token, order_id):
    """
    Capture a payment for an existing order

    Args:
        access_token (str): PayPal API access token
        order_id (str): Order ID

    Returns:
        str: Payment capture response

    Example:
        >>> access_token = get_access_token(username, password)
        >>> order_id = create_order(access_token, data_orders)
        >>> response_capture = capture_payment(access_token, order_id)
        >>> print(response_capture)
    """
    url_capture = 'https://api-m.sandbox.paypal.com/v1/checkout/orders/{}/capture'.format(order_id)
    response_capture = requests.post(url_capture, headers={'Authorization': 'Bearer {}'.format(access_token)})
    if response_capture.status_code == 201:
        return response_capture.text
    else:
        raise Exception('Error capturing payment: {}'.format(response_capture.text))

# Example usage
username = 'AdZ38dWwRg-vOQxAjv_ZAXDRp2K6xhm2w55BwnBVW8wH9jHKZKC3BYosJqqOZ1m0cs4z9U5yHc-IxefZ'
password = 'EH3ywSuqZTBoUQP9HEEOTGH7UfjPR2eGs3eVWcl1qeb3bw1q_6Cs1RDPyd-Kfl4pB0gdswzR3iFFL2UD'