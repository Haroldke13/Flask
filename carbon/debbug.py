# app/__init__.py
from flask import Flask, render_template
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_cors import CORS
import stripe
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
    stripe.api_key = app.config['STRIPE_TEST_SECRET_KEY']

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


forms.py

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, IntegerField, SubmitField,BooleanField,FloatField, SelectField, DecimalField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError, NumberRange
from app.models import User
from .models import User


class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    location = StringField('Location', validators=[Length(max=150)])
    household_size = IntegerField('Household Size', validators=[DataRequired()])
    vehicle_ownership = StringField('Vehicle Ownership', validators=[Length(max=150)])
    dietary_preference = StringField('Dietary Preference', validators=[Length(max=150)])
    submit = SubmitField('Sign Up')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class CarbonFootprintForm(FlaskForm):
    carbon_emissions = DecimalField('Total Carbon Emissions (kg CO2e)', validators=[DataRequired()])
    transportation_mode = SelectField('Transportation Mode', choices=[
        ('car', 'Car'),
        ('bus', 'Bus'),
        ('train', 'Train'),
        ('bike', 'Bike'),
        ('walk', 'Walk')
    ])
    transportation_distance = DecimalField('Transportation Distance (miles)', validators=[DataRequired()])
    transportation_fuel_type = SelectField('Fuel Type', choices=[
        ('petrol', 'Petrol'),
        ('diesel', 'Diesel'),
        ('electric', 'Electric'),
        ('hybrid', 'Hybrid')
    ])
    transportation_fuel_consumption = DecimalField('Fuel Consumption (gallons)', validators=[DataRequired()])
    electricity_usage = DecimalField('Electricity Usage (kWh)', validators=[DataRequired()])
    water_usage = DecimalField('Water Usage (gallons)', validators=[DataRequired()])
    food_consumption = DecimalField('Food Consumption Impact (kg CO2e)', validators=[DataRequired()])
    submit = SubmitField('Save')
    
    def serialize(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'carbon_emissions': self.carbon_emissions,
            'transportation_mode': self.transportation_mode,
            'transportation_distance': self.transportation_distance,
            'transportation_fuel_type': self.transportation_fuel_type,
            'transportation_fuel_consumption': self.transportation_fuel_consumption,
            'electricity_usage': self.electricity_usage,
            'water_usage': self.water_usage,
            'food_consumption': self.food_consumption
        }
        
        
        
class PaymentForm(FlaskForm):
    amount = DecimalField('Amount', validators=[DataRequired()])
    payment_method = SelectField('Payment Method', choices=[('paypal', 'PayPal'), ('card', 'Credit Card'), ('mpesa', 'M-Pesa Kenya')])
    submit = SubmitField('Pay Now')


models.py

# app/models.py
from datetime import datetime
from .extensions import db, login_manager
from flask_login import UserMixin
from.extensions import bcrypt


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password = db.Column(db.String(60), nullable=False)
    location = db.Column(db.String(150))
    household_size = db.Column(db.Integer)
    vehicle_ownership = db.Column(db.String(150))
    dietary_preference = db.Column(db.String(150))
    date_joined = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

class CarbonFootprint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    carbon_emissions = db.Column(db.Float)
    transportation_mode = db.Column(db.String(20))
    transportation_distance = db.Column(db.Float)
    transportation_fuel_type = db.Column(db.String(20))
    transportation_fuel_consumption = db.Column(db.Float)
    electricity_usage = db.Column(db.Float)
    water_usage = db.Column(db.Float)
    food_consumption = db.Column(db.Float)

    @property
    def levy(self):
        return self.carbon_emissions * 0.05  # Example calculation

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    project_id = db.Column(db.Integer, nullable=False)
    amount = db.Column(db.Float, nullable=False)
    payment_intent_id = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.now())
    updated_at = db.Column(db.DateTime, default=db.func.now(), onupdate=db.func.now())

    def serialize(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'project_id': self.project_id,
            'amount': self.amount,
            'payment_intent_id': self.payment_intent_id,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }

    
    routes.py
# app/routes.py
from flask import Blueprint, current_app, render_template, url_for, flash, redirect, request, jsonify
from flask_login import login_user, current_user, logout_user, login_required
from urllib.parse import urlparse
from .extensions import db
from .models import User, CarbonFootprint, Payment
from .forms import RegistrationForm, LoginForm, PaymentForm, CarbonFootprintForm
import stripe
import paypalrestsdk

bp = Blueprint('main', __name__)

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
        user = User(email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('main.login'))
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
        return redirect(url_for('main.dashboard'))
    return render_template('dashboard.html', title='Dashboard', form=form)

@bp.route('/results')
@login_required
def results():
    footprints = CarbonFootprint.query.filter_by(user_id=current_user.id).all()
    return render_template('results.html', title='Results', footprints=footprints)

@bp.route('/projects')
def projects():
    return render_template('projects.html', title='Projects')

@bp.route('/payments')
@login_required
def payments():
    payments = Payment.query.filter_by(user_id=current_user.id).all()
    return render_template('payments.html', payments=payments)

@bp.route('/payment', methods=['GET', 'POST'])
@login_required
def payment():
    stripe.api_key = current_app.config['STRIPE_TEST_SECRET_KEY']
    total_levy = sum(footprint.levy for footprint in CarbonFootprint.query.filter_by(user_id=current_user.id).all())
    form = PaymentForm()

    if form.validate_on_submit():
        payment_method = form.payment_method.data
        if payment_method == 'card':
            return redirect(url_for('main.pay_card', amount=total_levy))
        elif payment_method == 'paypal':
            return redirect(url_for('main.pay_paypal', amount=total_levy))
        elif payment_method == 'mpesa':
            return redirect(url_for('main.pay_mpesa', amount=total_levy))

    return render_template('payment.html',form=form)

@bp.route('/pay_card', methods=['POST'])
@login_required
def pay_card():
    stripe.api_key = current_app.config['STRIPE_TEST_SECRET_KEY']
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
        return jsonify({'success': False, 'error': str(e)})

@bp.route('/pay_paypal', methods=['POST'])
@login_required
def pay_paypal():
    data = request.get_json()
    amount = data.get('amount')

    try:
        paypalrestsdk.configure({
            'mode': 'sandbox',
            'client_id': current_app.config['PAYPAL_CLIENT_ID'],
            'client_secret': current_app.config['PAYPAL_CLIENT_SECRET']
        })

        payment = paypalrestsdk.Payment({
            "intent": "sale",
            "payer": {
                "payment_method": "paypal"
            },
            "transactions": [{
                "amount": {
                    "total": str(amount),
                    "currency": "USD"
                },
                "description": "Carbon footprint levy payment"
            }],
            "redirect_urls": {
                "return_url": url_for('main.paypal_return', _external=True),
                "cancel_url": url_for('main.paypal_cancel', _external=True)
            }
        })

        if payment.create():
            payment_id = payment.id
            return jsonify({'success': True, 'payment_id': payment_id})
        else:
            return jsonify({'success': False, 'error': payment.error})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@bp.route('/pay_mpesa', methods=['POST'])
@login_required
def pay_mpesa():
    # Implement M-Pesa integration here
    return jsonify({'success': False, 'error': 'M-Pesa integration not yet implemented'})

@bp.route('/stripe_payment/<payment_intent_id>', methods=['GET', 'POST'])
@login_required
def stripe_payment(payment_intent_id):
    stripe.api_key = current_app.config['STRIPE_TEST_SECRET_KEY']
    payment_intent = stripe.PaymentIntent.retrieve(payment_intent_id)
    
    if request.method == 'POST':
        try:
            payment_intent.confirm()
            flash('Payment successful!', 'success')
            return redirect(url_for('main.home'))
        except stripe.error.CardError as e:
            flash('Payment failed. Please try again.', 'danger')
    
    return render_template('stripe_payment.html', payment_intent=payment_intent)

@bp.route('/paypal_return')
@login_required
def paypal_return():
    payment_id = request.args.get('paymentId')
    payer_id = request.args.get('PayerID')

    payment = paypalrestsdk.Payment.find(payment_id)
    if payment.execute({"payer_id": payer_id}):
        flash('Payment successful!', 'success')
    else:
        flash('Payment failed. Please try again.', 'danger')

    return redirect(url_for('main.payments'))

@bp.route('/paypal_cancel')
@login_required
def paypal_cancel():
    flash('Payment was canceled.', 'warning')
    return redirect(url_for('main.payment'))



@bp.route('/handle_payment', methods=['POST'])
def handle_payment():
    data = request.get_json()
    payment_method = data.get('payment_method')
    amount = data.get('amount')
    token = data.get('token')

    # Logic to handle different payment methods
    if payment_method == 'card':
        # Process credit card payment with Stripe
        # Assuming you have a function to handle this
        payment_response = process_card_payment(amount, token)
        if payment_response['success']:
            return jsonify({'success': True, 'redirect_url': url_for('main.pay_card', amount=amount)})
        else:
            return jsonify({'success': False, 'error': payment_response['error']})

    elif payment_method == 'paypal':
        # Process PayPal payment
        # Assuming you have a function to handle this
        payment_response = process_paypal_payment(amount)
        if payment_response['success']:
            return jsonify({'success': True, 'redirect_url': url_for('main.pay_paypal', amount=amount)})
        else:
            return jsonify({'success': False, 'error': payment_response['error']})

    elif payment_method == 'mpesa':
        # Process M-Pesa payment
        # Assuming you have a function to handle this
        payment_response = process_mpesa_payment(amount)
        if payment_response['success']:
            return jsonify({'success': True, 'redirect_url': url_for('main.pay_mpesa', amount=amount)})
        else:
            return jsonify({'success': False, 'error': payment_response['error']})

    else:
        return jsonify({'success': False, 'error': 'Invalid payment method'})
    
    
    
    FILL IN THE FUNCTIONS TO OROCESS PAYMENT
    
    PAYMENT.HTML
    {% extends "base.html" %}

{% block title %}Confirm Payment{% endblock %}

{% block content %}
<div class="container">
    <h2 class="text-center mb-4">Confirm Payment</h2>
    <p class="text-center mb-4">Your carbon footprint levy is: <strong>${{ levy_amount }}</strong></p>
    <form id="payment-form" method="POST" action="{{ url_for('main.payment') }}">
        {{ form.hidden_tag() }}

        <div class="form-group">
            {{ form.amount.label(class="form-label") }}
            {{ form.amount(class="form-control", value=levy_amount, readonly=True) }}
        </div>

        <div class="form-group">
            {{ form.payment_method.label(class="form-label") }}
            {{ form.payment_method(class="form-control") }}
        </div>

        <div id="payment-details" style="display:none;">
            <!-- Additional fields for PayPal and M-Pesa can be added here -->
        </div>

        <div class="form-group mb-4" id="card-payment" style="display:none;">
            <label for="card-element" class="form-label">Credit or Debit Card</label>
            <div id="card-element" class="form-control">
                <!-- A Stripe Element will be inserted here. -->
            </div>
            <div id="card-errors" role="alert" class="mt-2 text-danger"></div>
        </div>

        <div class="form-group text-center">
            <button type="submit" id="submit-button" class="btn btn-success btn-lg w-100">Pay Now</button>
        </div>
    </form>
</div>
<script src="https://js.stripe.com/v3/"></script>
<script>
    document.addEventListener('DOMContentLoaded', function() {
        var stripe = Stripe('STRIPE_TEST_SECRET_KEY'); // Replace with your Stripe publishable key
        var elements = stripe.elements();
        
        var cardElement = elements.create('card', {
            hidePostalCode: true,
            style: {
                base: {
                    color: '#32325d',
                    fontSize: '16px',
                    '::placeholder': {
                        color: '#aab7c4'
                    }
                },
                invalid: {
                    color: '#fa755a',
                    iconColor: '#fa755a'
                }
            }
        });

        var form = document.getElementById('payment-form');
        var cardPayment = document.getElementById('card-payment');
        
        form.addEventListener('change', function(event) {
            var paymentMethod = document.querySelector('select[name="payment_method"]').value;
            if (paymentMethod === 'card') {
                cardPayment.style.display = 'block';
                cardElement.mount('#card-element');
            } else {
                cardPayment.style.display = 'none';
            }
        });

        form.addEventListener('submit', function(event) {
            event.preventDefault();
            
            var paymentMethod = document.querySelector('select[name="payment_method"]').value;
            var data = {
                amount: {{ levy_amount }},
                payment_method: paymentMethod
            };

            if (paymentMethod === 'card') {
                stripe.createToken(cardElement).then(function(result) {
                    if (result.error) {
                        var errorElement = document.getElementById('card-errors');
                        errorElement.textContent = result.error.message;
                    } else {
                        data.token = result.token.id;
                        submitPayment(data);
                    }
                });
            } else {
                submitPayment(data);
            }
        });

        function submitPayment(data) {
            fetch('{{ url_for("main.handle_payment") }}', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': '{{ csrf_token() }}'
                },
                body: JSON.stringify(data)
            }).then(function(response) {
                return response.json();
            }).then(function(data) {
                if (data.success) {
                    if (data.redirect_url) {
                        window.location.href = data.redirect_url;
                    } else {
                        window.location.href = '/'; // Redirect to home or a success page
                    }
                } else {
                    var errorElement = document.getElementById('card-errors');
                    errorElement.textContent = data.error;
                }
            }).catch(function(error) {
                var errorElement = document.getElementById('card-errors');
                errorElement.textContent = 'An unexpected error occurred. Please try again.';
            });
        }
    });
</script>
{% endblock %}


base.HTML
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}Carbon Footprint Calculator{% endblock %}</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <style>
        .navbar-custom {
            background-color: #d62a6d; /* Dark Pink */
        }

        .navbar-custom .navbar-brand,
        .navbar-custom .nav-link {
            color: white; /* White text */
        }

        .navbar-custom .nav-link:active {
            color: black; /* Black text on click */
        }

        .navbar-right {
            margin-left: auto; /* Push to the far right */
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-custom">
        <a class="navbar-brand" href="{{ url_for('main.home') }}">Carbon Footprint</a>
        <div class="collapse navbar-collapse d-flex justify-content-between" id="navbarNav">
            <ul class="navbar-nav">
                <li class="nav-item">
                    <a class="nav-link" href="{{ url_for('main.home') }}">Home</a>
                </li>
                {% if current_user.is_authenticated %}
                <li class="nav-item">
                    <a class="nav-link" href="{{ url_for('main.dashboard') }}">Dashboard</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="{{ url_for('main.results') }}">Results</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="{{ url_for('main.projects') }}">Projects</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="{{ url_for('main.payments') }}">Payments</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="{{ url_for('main.payment') }}">Pay your Eco Levy </a>

                </li>
                
                <li class="nav-item">
                    <a class="nav-link" href="{{ url_for('main.logout') }}">Logout</a>
                </li>
                <li class="nav-item navbar-right">
                    <span class="navbar-text">{{ current_user.email }}</span>
                </li>
                {% else %}
                <li class="nav-item">
                    <a class="nav-link" href="{{ url_for('main.login') }}">Login</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="{{ url_for('main.register') }}">Register</a>
                </li>
                {% endif %}
            </ul>
        </div>
    </nav>

    <div class="container">
        {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
        {% for category, message in messages %}
        <div class="alert alert-{{ category }}">{{ message }}</div>
        {% endfor %}
        {% endif %}
        {% endwith %}
        {% block content %}{% endblock %}
    </div>

    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.5.3/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</body>
</html>



have the payment.html page  AMOUNT, show the carbon footprint levy value 