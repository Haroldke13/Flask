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
    username = db.Column(db.String(150), nullable=False)  # Add this line
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
