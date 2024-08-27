# Carbon Footprint Calculator

## Overview
This project is a web application built with Flask that helps users calculate and manage their carbon footprint. The application includes features such as user registration, login, carbon footprint calculation, and payment processing using Stripe, PayPal, and M-Pesa.

## Features
- User Authentication (Registration and Login)
- Carbon Footprint Calculator
- Payment Integration with Stripe, PayPal, and M-Pesa
- Secure handling of sensitive information using environment variables
- CSRF protection

## Technologies Used
- Flask
- SQLAlchemy
- Flask-WTF
- Stripe API
- PayPal SDK
- M-Pesa (planned integration)
- Bootstrap for styling

## Setup and Installation

1. **Clone the repository:**

    ```bash
    git clone https://github.com/Haroldke13/Flask.git
    cd carbon
    ```

2. **Create and activate a virtual environment:**

    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3. **Install dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

4. **Initialize datatbases :**

    ```bash
    rm -rf instance
    rm -rf migrations
    flask db init
    flask db migrate
    flask db upgrade
    ```

5. **Run the application:**

    ```bash
    flask run
    ```

6. **Access the application:**

    Visit `http://127.0.0.1:5000` in your web browser.

## Payment Integration
- **Stripe:** Integrated for credit card payments.
- **PayPal:** Integrated for PayPal payments.
- **M-Pesa:** M-Pesa payment integration is planned.

## Folder Structure
- `app/`: Contains all the main application code.
- `app/models.py`: Defines the database models.
- `app/routes.py`: Defines the application routes.
- `app/forms.py`: Contains the form classes.
- `app/templates/`: Contains the HTML templates.
- `instance/`: Contains the application instance files.
- `app/static/css/` : Contains styling file 

## Contributing
If you would like to contribute to this project, feel free to submit a pull request or open an issue. The project is in the public domain.

## License
This project is licensed under the MIT License.
