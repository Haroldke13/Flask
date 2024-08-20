from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, IntegerField, SubmitField,BooleanField,FloatField, SelectField, DecimalField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError, NumberRange
from app.models import User
from .models import User


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message="Passwords must match.")])
    location = StringField('Location', validators=[DataRequired(),Length(max=150)])
    household_size = IntegerField('Household Size', validators=[DataRequired(), NumberRange(min=1, message="Household size must be a positive number.")])
    vehicle_ownership = StringField('Vehicle Ownership', validators=[DataRequired(),Length(max=150)])
    dietary_preference = StringField('Dietary Preference', validators=[DataRequired(),Length(max=150)])
    submit = SubmitField('Register')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is already in use. Please choose a different one.')


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
        
        
        

    
    
class EditProfileForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    location = StringField('Location', validators=[Length(max=150)])
    household_size = IntegerField('Household Size', validators=[DataRequired()])
    vehicle_ownership = StringField('Vehicle Ownership', validators=[Length(max=150)])
    dietary_preference = StringField('Dietary Preference', validators=[Length(max=150)])
    submit = SubmitField('Update')



class PaymentForm(FlaskForm):
    amount = DecimalField('Amount', validators=[DataRequired()])
    payment_method = SelectField('Payment Method', choices=[('paypal', 'PayPal'), ('card', 'Credit Card'), ('mpesa', 'M-Pesa Kenya')], validators=[DataRequired()])
    paypal_email = StringField('PayPal Email', validators=[Email()])
    mpesa_phone = StringField('M-Pesa Phone Number')
    submit = SubmitField('Buy Now')