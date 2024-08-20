# app/extensions.py
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
import paypalrestsdk
from flask import current_app



db = SQLAlchemy()
login_manager = LoginManager()
bcrypt = Bcrypt()




def get_paypal_config():
    """Return PayPal configuration from current app context."""
    return {
        'mode': 'sandbox',
        'client_id': 'AdZ38dWwRg-vOQxAjv_ZAXDRp2K6xhm2w55BwnBVW8wH9jHKZKC3BYosJqqOZ1m0cs4z9U5yHc-IxefZ',
        'client_secret': 'EH3ywSuqZTBoUQP9HEEOTGH7UfjPR2eGs3eVWcl1qeb3bw1q_6Cs1RDPyd-Kfl4pB0gdswzR3iFFL2UD'
    }