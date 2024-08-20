from flask import Flask,render_template
from flask_wtf.csrf import CSRFProtect
from flask_cors import CORS
from flask_migrate import Migrate
import stripe
import paypalrestsdk
from .extensions import db, login_manager, bcrypt
from .routes import bp as main_bp

def create_app():
    app = Flask(__name__)

    # Load configurations from config file
    app.config.from_object('config.Config')

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    bcrypt.init_app(app)
    CSRFProtect(app)
    CORS(app)
    Migrate(app, db)

    # Initialize Stripe with the configuration
    stripe.api_key = app.config['STRIPE_LIVE_SECRET_KEY']

    # Initialize PayPal SDK with configuration
    paypalrestsdk.configure({
        'mode': 'sandbox',  # Change to 'live' for production
        'client_id': 'AdZ38dWwRg-vOQxAjv_ZAXDRp2K6xhm2w55BwnBVW8wH9jHKZKC3BYosJqqOZ1m0cs4z9U5yHc-IxefZ',
        'client_secret': 'EH3ywSuqZTBoUQP9HEEOTGH7UfjPR2eGs3eVWcl1qeb3bw1q_6Cs1RDPyd-Kfl4pB0gdswzR3iFFL2UD'
    })

    # Register blueprints
    app.register_blueprint(main_bp)

    # Error handlers
    register_error_handlers(app)

    return app

def register_error_handlers(app):
    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('404.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()  # Rollback session to prevent issues on next DB call
        return render_template('500.html'), 500
