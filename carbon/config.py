import os
from flask import current_app
import paypalrestsdk
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect()


class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'do_not_show_this_to_anyone_100')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///site.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    CORS_HEADERS = 'Content-Type'
    STRIPE_TEST_PUBLIC_KEY = 'pk_live_51HwGnJKnqvVfR1oRX9y5t6mD6yT8JL6dp29xODsWqn3r5DsQ7RpjVrZnJq'
    STRIPE_TEST_SECRET_KEY = 'pk_live_51HwGnJKnqvVfR1oRX9y5t6mD6yT8JL6dp29xODsWqn3r5DsQ7RpjVrZnJq'
    STRIPE_LIVE_SECRET_KEY = 'sk_live_51HwGnJKnqvVfR1oRX9y5t6mD6yT8JL6dp29xODsWqn3r5DsQ7RpjVrZnJq'  # Secret Key
    STRIPE_LIVE_PUBLISHABLE_KEY = 'pk_live_51HwGnJKnqvVfR1oRX9y5t6mD6yT8JL6dp29xODsWqn3r5DsQ7RpjVrZnJq'  # Publishable Key
    PAYPAL_CLIENT_ID = 'AdZ38dWwRg-vOQxAjv_ZAXDRp2K6xhm2w55BwnBVW8wH9jHKZKC3BYosJqqOZ1m0cs4z9U5yHc-IxefZ'
    PAYPAL_CLIENT_SECRET = 'EH3ywSuqZTBoUQP9HEEOTGH7UfjPR2eGs3eVWcl1qeb3bw1q_6Cs1RDPyd-Kfl4pB0gdswzR3iFFL2UD'
    
    

    




    
