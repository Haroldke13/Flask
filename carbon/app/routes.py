# app/routes.py
import json
from flask import Blueprint, current_app, render_template, url_for, flash, redirect, request, jsonify
from flask_login import login_user, current_user, logout_user, login_required
from urllib.parse import urlparse
from .extensions import db
from .models import User, CarbonFootprint, Payment
from .forms import RegistrationForm, LoginForm, PaymentForm, CarbonFootprintForm,EditProfileForm
import stripe
import paypalrestsdk
from .extensions import get_paypal_config
import requests
import base64
from .paypal_client import get_access_token, create_order, capture_payment
import os
from flask_wtf.csrf import CSRFProtect






# Url for the POST request
paypal_url = 'https://api.sandbox.paypal.com/v1/oauth2/token'
PAYPAL_CLIENT_ID  = 'AdZ38dWwRg-vOQxAjv_ZAXDRp2K6xhm2w55BwnBVW8wH9jHKZKC3BYosJqqOZ1m0cs4z9U5yHc-IxefZ'
PAYPAL_CLIENT_SECRET =  'EH3ywSuqZTBoUQP9HEEOTGH7UfjPR2eGs3eVWcl1qeb3bw1q_6Cs1RDPyd-Kfl4pB0gdswzR3iFFL2UD'

bp = Blueprint('main', __name__)


import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def log_error(error_message):
    """Helper function to log errors with additional user context."""
    logger.error(f"User: {current_user.id if current_user.is_authenticated else 'Anonymous'} | Error: {error_message}")



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


@bp.route('/get_paypal_token', methods=['GET'])
def get_paypal_token_route():
    """Route to retrieve PayPal OAuth 2.0 token."""
    token = get_paypal_token()
    if token:
        return jsonify({'success': True, 'token': token})
    else:
        return jsonify({'success': False, 'error': 'Failed to retrieve PayPal token'})


@bp.route('/')
@bp.route('/home')
def home():
    return render_template('home.html')


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

@bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('main.home'))

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

@bp.route('/results')
@login_required
def results():
    footprints = CarbonFootprint.query.filter_by(user_id=current_user.id).all()
    total_levy = sum(footprint.levy for footprint in footprints)  # Calculate the total levy
    return render_template('results.html', title='Results', footprints=footprints, total_levy=total_levy)


@bp.route('/projects')
def projects():
    return render_template('projects.html', title='Projects')

@bp.route('/payments')
@login_required
def payments():
    payments = Payment.query.filter_by(user_id=current_user.id).all()
    return render_template('payments.html', payments=payments)


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

    return render_template('payment.html', form=form, stripe_publishable_key=stripe_publishable_key, levy=total_levy)

@bp.route('/pay_paypal', methods=['POST'])
@login_required
def pay_paypal():
    amount = request.args.get('amount')
    access_token = get_access_token(current_app.config['PAYPAL_CLIENT_ID'], current_app.config['PAYPAL_CLIENT_SECRET'])

    if not access_token:
        return jsonify({'success': False, 'error': 'Failed to obtain PayPal token'})

    order_data = {
        'intent': 'CAPTURE',
        'purchase_units': [
            {
                'amount': {
                    'currency_code': 'USD',
                    'value': amount,
                    'breakdown': {
                        'item_total': {
                            'currency_code': 'USD',
                            'value': amount
                        }
                    }
                }
            }
        ],
        'application_context': {
            'return_url': url_for('main.paypal_return', _external=True),
            'cancel_url': url_for('main.paypal_cancel', _external=True)
        }
    }

    try:
        order_id = create_order(access_token, order_data)
        approval_url = f"https://www.sandbox.paypal.com/checkoutnow?token={order_id}"
        return jsonify({'success': True, 'redirect_url': approval_url})
    except Exception as e:
        log_error(f"PayPal payment request failed: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})





@bp.route('/paypal_return')
@login_required
def paypal_return():
    order_id = request.args.get('token')
    access_token = get_access_token(current_app.config['PAYPAL_CLIENT_ID'], current_app.config['PAYPAL_CLIENT_SECRET'])

    if not access_token:
        flash('Failed to capture PayPal payment. Please try again.', 'danger')
        return redirect(url_for('main.payment'))

    try:
        capture_response = capture_payment(access_token, order_id)
        flash('Payment successful!', 'success')

        # Record the payment in the database
        payment = Payment(
            user_id=current_user.id,
            project_id=1,  # Update this with the actual project_id
            amount=request.args.get('amount'),
            payment_intent_id=order_id
        )
        db.session.add(payment)
        db.session.commit()

        return redirect(url_for('main.payments'))
    except Exception as e:
        log_error(f"PayPal capture failed: {str(e)}")
        flash('Payment capture failed. Please try again.', 'danger')
        return redirect(url_for('main.payment'))






@bp.route('/stripe_payment/<payment_intent_id>', methods=['GET', 'POST'])
@login_required
def stripe_payment(payment_intent_id):
    stripe.api_key = current_app.config['STRIPE_TEST_PUBLIC_KEY']
    payment_intent = stripe.PaymentIntent.retrieve(payment_intent_id)
    
    if request.method == 'POST':
        try:
            payment_intent.confirm()
            flash('Payment successful!', 'success')
            return redirect(url_for('main.home'))
        except stripe.error.CardError as e:
            flash('Payment failed. Please try again.', 'danger')
    
    return render_template('stripe_payment.html', payment_intent=payment_intent)




@bp.route('/paypal_cancel')
@login_required
def paypal_cancel():
    flash('Payment was canceled.', 'warning')
    return redirect(url_for('main.payment'))



@bp.route('/handle_payment', methods=['POST'])
@login_required
def handle_payment():
    try:
        data = request.json  # Ensure you're receiving JSON data
        payment_method = data.get('payment_method')
        amount = float(data.get('amount'))
        currency = "USD"

        # Process the payment based on the method
        if payment_method == 'paypal':
            paypal_access_token = get_paypal_access_token()
            if not paypal_access_token:
                return jsonify(success=False, error="Failed to authenticate PayPal.")

            paypal_order_id = create_paypal_order(amount, currency, paypal_access_token)
            if not paypal_order_id:
                return jsonify(success=False, error="Failed to create PayPal order.")

            redirect_url = f"https://www.sandbox.paypal.com/checkoutnow?token={paypal_order_id}"
            return jsonify(success=True, redirect_url=redirect_url)

        elif payment_method == 'card':
            stripe_token = data.get('stripeToken')
            if not stripe_token:
                return jsonify(success=False, error="Stripe token is missing.")

            try:
                charge = stripe.Charge.create(
                    amount=int(amount * 100),
                    currency=currency,
                    source=stripe_token,
                    description="Carbon-Friendly Product Purchase"
                )
                return jsonify(success=True, redirect_url=url_for('payment_success'))
            except stripe.error.StripeError as e:
                return jsonify(success=False, error=str(e))

        elif payment_method == 'mpesa':
            mpesa_phone = data.get('mpesa_phone')
            if not mpesa_phone:
                return jsonify(success=False, error="M-Pesa phone number is missing.")

            # Placeholder for M-Pesa logic
            return jsonify(success=True, redirect_url=url_for('payment_success'))

        else:
            return jsonify(success=False, error="Invalid payment method selected.")

    except Exception as e:
        return jsonify(success=False, error=str(e))

@bp.route('/payment_success')
@login_required
def payment_success():
    return render_template('payment_success.html')

    
def process_paypal_payment(amount):
    try:
        paypalrestsdk.configure({
                'mode': 'sandbox', # or 'live'
                'client_id': current_app.config['PAYPAL_CLIENT_ID'],
                'client_secret': current_app.config['PAYPAL_CLIENT_SECRET']
            })


        payment = paypalrestsdk.Payment({
            "intent": "sale",
            "payer": {"payment_method": "paypal"},
            "transactions": [{
                "amount": {"total": str(amount), "currency": "USD"},
                "description": "Carbon footprint levy payment"
            }],
            "redirect_urls": {
                "return_url": url_for('main.paypal_return', _external=True),
                "cancel_url": url_for('main.paypal_cancel', _external=True)
            }
        })

        if payment.create():
            approval_url = next(link.href for link in payment.links if link.rel == "approval_url")
            return {'success': True, 'redirect_url': approval_url}
        else:
            error_msg = payment.error.get('message', 'PayPal payment creation failed.')
            return {'success': False, 'error': error_msg}
    except Exception as e:
        return {'success': False, 'error': str(e)}





@bp.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)




@bp.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm()

    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your profile has been updated!', 'success')
        return redirect(url_for('main.profile'))  # Redirect to profile page after update

    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email

    return render_template('edit_profile.html', title='Edit Profile', form=form)



def get_paypal_access_token():
    # Fetch PayPal access token using client credentials
    url = "https://api.sandbox.paypal.com/v1/oauth2/token"
    headers = {
        "Accept": "application/json",
        "Accept-Language": "en_US",
    }
    data = {
        "grant_type": "client_credentials"
    }
    response = requests.post(url, headers=headers, data=data, auth=(PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET))
    if response.status_code == 200:
        return response.json().get('access_token')
    return None

def create_paypal_order(amount, currency, access_token):
    # Create a PayPal order
    url = "https://api.sandbox.paypal.com/v2/checkout/orders"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}"
    }
    data = {
        "intent": "CAPTURE",
        "purchase_units": [{
            "amount": {
                "currency_code": currency,
                "value": str(amount)
            }
        }]
    }
    response = requests.post(url, headers=headers, json=data)
    if response.status_code == 201:
        return response.json().get('id')  # Return the PayPal order ID
    return None




# Route to display products
@bp.route('/products')
def products():
    

    products = [
        {'id': i+1, 'name': f'Carbon-Friendly Product {i+1}', 'description': 'Environmentally friendly product', 'price': 10.00} 
        for i in range(50)
    ]
    return render_template('products.html', products=products)


# Route to handle payments
@bp.route('/handle_payments', methods=['POST'])
def handle_payments():
    product_id = request.form.get('product_id')
    product_name = request.form.get('product_name')
    product_price = request.form.get('product_price')
    
    try:
        access_token = get_access_token()

        # Create order
        data_orders = {
            'intent': 'CAPTURE',
            'purchase_units': [
                {
                    'items': [
                        {
                            'name': product_name,
                            'description': 'carbon footprint levy',
                            'quantity': '1',
                            'unit_amount': {
                                'currency_code': 'USD',
                                'value': product_price
                            }
                        }
                    ],
                    'amount': {
                        'currency_code': 'USD',
                        'value': product_price,
                        'breakdown': {
                            'item_total': {
                                'currency_code': 'USD',
                                'value': product_price
                            }
                        }
                    }
                }
            ],
            'application_context': {
                'return_url': url_for('payment_success', _external=True),
                'cancel_url': url_for('payment_cancel', _external=True)
            }
        }

        order_id = create_order(access_token, data_orders)

        # Redirect user to PayPal for payment
        return redirect(f"https://www.sandbox.paypal.com/checkoutnow?token={order_id}")

    except Exception as e:
        return str(e)



# Route for payment cancellation
@bp.route('/payment_cancel')
def payment_cancel():
    return "Payment was cancelled. Please try again."

def create_order(access_token, data_orders):
    url_orders = 'https://api-m.sandbox.paypal.com/v1/checkout/orders'
    response_orders = requests.post(url_orders, json=data_orders, headers={'Authorization': f'Bearer {access_token}'})
    if response_orders.status_code == 201:
        return json.loads(response_orders.text)['id']
    else:
        raise Exception('Error creating order: {}'.format(response_orders.text))
