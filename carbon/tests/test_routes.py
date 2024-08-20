import pytest
from app import create_app, db
from app.models import User


@pytest.fixture(scope='module')
def new_user():
    user = User(email='testuser@example.com', password='password')
    return user

@pytest.fixture(scope='module')
def test_client():
    flask_app = create_app()
    flask_app.config.from_object('config.TestingConfig')
    testing_client = flask_app.test_client()
    with flask_app.app_context():
        db.create_all()
        yield testing_client
        db.drop_all()
def test_register(test_client):
    response = test_client.post('/register', data=dict(
    email='test@example.com', password='password',
    confirm_password='password',
    location='Test Location', household_size=2,
    vehicle_ownership='Yes', dietary_preference='Vegan' ), follow_redirects=True)
    assert response.status_code == 200
    assert b'Registration successful!' in response.data
    
    
def test_login(test_client, new_user):
    test_client.post('/register', data=dict(email=new_user.email, password=new_user.password,confirm_password=new_user.password,location='Test Location', household_size=2,vehicle_ownership='Yes', dietary_preference='Vegan'), follow_redirects=True)
    response = test_client.post('/login',data=dict(email=new_user.email, password=new_user.password), follow_redirects=True)
    assert response.status_code == 200
    assert b'Dashboard' in response.data