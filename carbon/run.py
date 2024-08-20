from app import create_app
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect()

app = create_app()

if __name__ == '__main__':
    app.run(debug=True, port= 10000)