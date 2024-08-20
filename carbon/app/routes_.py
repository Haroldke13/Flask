from flask import Blueprint, current_app, render_template, url_for, flash, redirect, request, jsonify
from flask_login import login_user, current_user, logout_user, login_required
from urllib.parse import urlparse
from .extensions import db
from .models import User, CarbonFootprint, Payment
from .forms import RegistrationForm, LoginForm, PaymentForm, CarbonFootprintForm, EditProfileForm
import stripe
import paypalrestsdk
import requests
import base64
import os
import logging

# Setting up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Blueprint for the main routes
bp = Blueprint('main', __name__)

# PayPal API details
paypal_url = 'https://api.sandbox.paypal.com/v1/oauth2/token'
PAYPAL_CLIENT_ID  = 'AdZ38dWwRg-vOQxAjv_ZAXDRp2K6xhm2w55BwnBVW8wH9jHKZKC3BYosJqqOZ1m0cs4z9U5yHc-IxefZ'
PAYPAL_CLIENT_SECRET =  'EH3ywSuqZTBoUQP9HEEOTGH7UfjPR2eGs3eVWcl1qeb3bw1q_6Cs1RDPyd-Kfl4pB0gdswzR3iFFL2UD'

# Function to log errors with user context
def log_error(error_message):
    """Helper function to log errors with additional user context."""
    logger.error(f"User: {current_user.id if current_user.is_authenticated else 'Anonymous'} | Error: {error_message}")

# Function to get PayPal OAuth 2.0 token
def get_paypal_token():
    client_id = current_app.config['PAYPAL_CLIENT_ID']
    client_secret = current_app.config['PAYPAL_CLIENT_SECRET']

    auth = f"{client_id}:{client_secret}"
    encoded_auth = base64.b64encode(auth.encode()).decode()

    headers = {
        "Authorization": f"Basic {encoded_auth}",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    data = {
        "grant_type": "client_credentials"
    }

    try:
        response = requests.post(paypal_url, headers=headers, data=data)
        response.raise_for_status()
        token_info = response.json()
        return token_info.get('access_token')
    except requests.exceptions.RequestException as e:
        log_error(f"PayPal token request failed: {str(e)}")
        return None

# Route to retrieve PayPal OAuth 2.0 token
@bp.route('/get_paypal_token', methods=['GET'])
def get_paypal_token_route():
    token = get_paypal_token()
    if token:
        return jsonify({'success': True, 'token': token})
    else:
        return jsonify({'success': False, 'error': 'Failed to retrieve PayPal token'})

# Home route
@bp.route('/')
@bp.route('/home')
def home():
    return render_template('home.html')

# User registration route
@bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        if form.username.data:
            user = User(username=form.username.data, email=form.email.data)
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            flash('Your account has been created! You are now able to log in', 'success')
            return redirect(url_for('main.login'))
        else:
            flash('Username is required.', 'danger')
    return render_template('register.html', title='Register', form=form)

# User login route
@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            if not next_page or urlparse(next_page).netloc != '':
                next_page = url_for('main.home')
            return redirect(next_page)
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

# User logout route
@bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('main.home'))

# Dashboard route where users can input their carbon footprint data
@bp.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = CarbonFootprintForm()
    if form.validate_on_submit():
        try:
            carbon_footprint = CarbonFootprint(
                user_id=current_user.id,
                carbon_emissions=form.carbon_emissions.data,
                transportation_mode=form.transportation_mode.data,
                transportation_distance=form.transportation_distance.data,
                transportation_fuel_type=form.transportation_fuel_type.data,
                transportation_fuel_consumption=form.transportation_fuel_consumption.data,
                electricity_usage=form.electricity_usage.data,
                water_usage=form.water_usage.data,
                food_consumption=form.food_consumption.data
            )
            db.session.add(carbon_footprint)
            db.session.commit()
            flash('Carbon footprint data has been saved!', 'success')
        except Exception as e:
            db.session.rollback()
            log_error(f"Error saving carbon footprint data: {str(e)}")
            flash('An error occurred while saving your data. Please try again later.', 'danger')
        return redirect(url_for('main.dashboard'))
    return render_template('dashboard.html', title='Dashboard', form=form)

# Results page to show the user's carbon footprint data
@bp.route('/results')
@login_required
def results():
    footprints = CarbonFootprint.query.filter_by(user_id=current_user.id).all()
    total_levy = sum(footprint.levy for footprint in footprints)  # Calculate the total levy
    return render_template('results.html', title='Results', footprints=footprints, total_levy=total_levy)

# Projects page
@bp.route('/projects')
def projects():
    return render_template('projects.html', title='Projects')

# Payments history page
@bp.route('/payments')
@login_required
def payments():
    payments = Payment.query.filter_by(user_id=current_user.id).all()
    return render_template('payments.html', payments=payments)

# Route to handle credit card payments using Stripe
@bp.route('/pay_card', methods=['POST'])
@login_required
def pay_card():
    stripe.api_key = current_app.config['STRIPE_TEST_PUBLIC_KEY']
    data = request.get_json()
    token = data.get('token')
    amount = data.get('amount')

    try:
        intent = stripe.PaymentIntent.create(
            amount=int(float(amount) * 100),  # Stripe expects amount in cents
            currency='usd',
            payment_method=token,
            confirm=True
        )

        payment = Payment(
            user_id=current_user.id,
            project_id=1,  # This would be dynamic in a real-world scenario
            amount=float(amount),
            payment_intent_id=intent.id
        )
        db.session.add(payment)
        db.session.commit()

        return jsonify({'success': True})

    except stripe.error.CardError as e:
        logger.error(f"Card Error: {str(e)}")
        return jsonify({'success': False, 'error': 'Card declined. Please check your card details and try again.'})
    except stripe.error.RateLimitError as e:
        logger.error(f"Rate Limit Error: {str(e)}")
        return jsonify({'success': False, 'error': 'Too many requests. Please try again later.'})
    except stripe.error.InvalidRequestError as e:
        logger.error(f"Invalid Request Error: {str(e)}")
        return jsonify({'success': False, 'error': 'Invalid payment request. Please contact support.'})
    except stripe.error.AuthenticationError as e:
        logger.error(f"Authentication Error: {str(e)}")
        return jsonify({'success': False, 'error': 'Authentication with payment gateway failed. Please try again.'})
    except stripe.error.APIConnectionError as e:
        logger.error(f"Network Error: {str(e)}")
        return jsonify({'success': False, 'error': 'Network error. Please check your connection and try again.'})
    except stripe.error.StripeError as e:
        logger.error(f"Stripe Error: {str(e)}")
        return jsonify({'success': False, 'error': 'Something went wrong. Please try again later.'})
    except Exception as e:
        logger.error(f"General Error: {str(e)}")
        return jsonify({'success': False, 'error': 'An error occurred. Please contact support.'})

# Payment processing page to choose a payment method
@bp.route('/payment', methods=['GET', 'POST'])
@login_required
def payment():
    stripe_publishable_key = current_app.config['STRIPE_TEST_PUBLIC_KEY']
    total_levy = sum(footprint.levy for footprint in CarbonFootprint.query.filter_by(user_id=current_user.id).all())
    form = PaymentForm()

    if form.validate_on_submit():
        try:
            payment_method = form.payment_method.data
            if payment_method == 'card':
                return redirect(url_for('main.pay_card', amount=total_levy))
            elif payment_method == 'paypal':
                return redirect(url_for('main.pay_paypal', amount=total_levy))
            elif payment_method == 'mpesa':
                return redirect(url_for('main.pay_mpesa', amount=total_levy))
            else:
                raise ValueError("Invalid payment method selected")
        except Exception as e:
            log_error(f"Payment processing error: {str(e)}")
            flash('An error occurred while processing your payment. Please try again later.', 'danger')
            return redirect(url_for('main.payment'))

    return render_template('payment.html', title='Payment', form=form, stripe_publishable_key=stripe_publishable_key)

# PayPal payment processing route
@bp.route('/pay_paypal', methods=['POST'])
@login_required
def pay_paypal():
    total_levy = request.form.get('amount')
    token = get_paypal_token()
    if not token:
        flash('PayPal token could not be retrieved. Please try again later.', 'danger')
        return redirect(url_for('main.payment'))

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    data = {
        "intent": "sale",
        "payer": {
            "payment_method": "paypal"
        },
        "transactions": [
            {
                "amount": {
                    "total": str(total_levy),
                    "currency": "USD"
                },
                "description": "Carbon Footprint Levy"
            }
        ],
        "redirect_urls": {
            "return_url": url_for('main.paypal_return', _external=True),
            "cancel_url": url_for('main.payment', _external=True)
        }
    }

    try:
        response = requests.post(f"{paypal_url}/v1/payments/payment", json=data, headers=headers)
        response.raise_for_status()
        payment_data = response.json()

        approval_url = None
        for link in payment_data.get('links', []):
            if link.get('rel') == 'approval_url':
                approval_url = link.get('href')
                break

        if approval_url:
            return redirect(approval_url)
        else:
            raise ValueError("Approval URL not found in PayPal response")

    except requests.exceptions.RequestException as e:
        log_error(f"PayPal payment creation failed: {str(e)}")
        flash('An error occurred while processing your PayPal payment. Please try again later.', 'danger')
        return redirect(url_for('main.payment'))

# Handle the return from PayPal after payment authorization
@bp.route('/paypal_return')
@login_required
def paypal_return():
    payment_id = request.args.get('paymentId')
    payer_id = request.args.get('PayerID')
    token = get_paypal_token()
    if not token:
        flash('PayPal token could not be retrieved. Please try again later.', 'danger')
        return redirect(url_for('main.payment'))

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(f"{paypal_url}/v1/payments/payment/{payment_id}/execute", json={"payer_id": payer_id}, headers=headers)
        response.raise_for_status()
        payment_data = response.json()

        payment = Payment(
            user_id=current_user.id,
            project_id=1,
            amount=float(payment_data['transactions'][0]['amount']['total']),
            payment_intent_id=payment_id
        )
        db.session.add(payment)
        db.session.commit()

        flash('Payment successful!', 'success')
        return redirect(url_for('main.payments'))

    except requests.exceptions.RequestException as e:
        log_error(f"PayPal payment execution failed: {str(e)}")
        flash('An error occurred while executing your PayPal payment. Please try again later.', 'danger')
        return redirect(url_for('main.payment'))

# M-Pesa payment processing route
@bp.route('/pay_mpesa', methods=['POST'])
@login_required
def pay_mpesa():
    total_levy = request.form.get('amount')
    mpesa_phone_number = request.form.get('mpesa_phone_number')

    if not mpesa_phone_number:
        flash('Please enter your M-Pesa phone number.', 'danger')
        return redirect(url_for('main.payment'))

    try:
        # Integrate with M-Pesa API here to process the payment
        # This is a placeholder for the M-Pesa payment logic
        payment_successful = True

        if payment_successful:
            payment = Payment(
                user_id=current_user.id,
                project_id=1,
                amount=total_levy,
                payment_intent_id="mpesa_placeholder_id"
            )
            db.session.add(payment)
            db.session.commit()

            flash('Payment successful!', 'success')
            return redirect(url_for('main.payments'))

        else:
            raise ValueError("M-Pesa payment failed")

    except Exception as e:
        log_error(f"M-Pesa payment error: {str(e)}")
        flash('An error occurred while processing your M-Pesa payment. Please try again later.', 'danger')
        return redirect(url_for('main.payment'))

# Route for editing the user profile
@bp.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm()
    if form.validate_on_submit():
        try:
            current_user.username = form.username.data
            current_user.email = form.email.data
            db.session.commit()
            flash('Your profile has been updated!', 'success')
        except Exception as e:
            db.session.rollback()
            log_error(f"Error updating profile: {str(e)}")
            flash('An error occurred while updating your profile. Please try again later.', 'danger')
        return redirect(url_for('main.edit_profile'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    return render_template('edit_profile.html', title='Edit Profile', form=form)

# Error handlers for common errors
@bp.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@bp.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('errors/500.html'), 500

