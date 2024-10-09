from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
import os
import re

# Initialize the Flask application
app = Flask(__name__)
app.secret_key = os.urandom(24)

# Database setup
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Session setup for server-side sessions using database
app.config['SESSION_TYPE'] = 'sqlalchemy'  # Use database for session storage
app.config['SESSION_SQLALCHEMY'] = db  # Use the same database for sessions
Session(app)  # Initialize the session extension

# Define the User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    
    # Relationship with purchases
    purchases = db.relationship('Purchase', back_populates='user')

# Define the CloudService model
class CloudService(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    
    # Relationship with purchases
    purchases = db.relationship('Purchase', back_populates='service')

# Define the Purchase model
class Purchase(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    service_id = db.Column(db.Integer, db.ForeignKey('cloud_service.id'), nullable=False)
    
    # Relationships with User and CloudService
    user = db.relationship('User', back_populates='purchases')
    service = db.relationship('CloudService', back_populates='purchases')

# Define the Suggestion model (for tool suggestions)
class Suggestion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)

# Home route (root URL)
@app.route('/')
def index():
    return render_template('index.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the user exists and password matches
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))

        flash('Invalid username or password.', 'error')
        return redirect(url_for('login'))

    # Render login page
    return render_template('login.html')

# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        # Password validation
        if not validate_password(password):
            flash('Password must include at least one uppercase letter, one lowercase letter, one digit, and one special character.', 'error')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)

        # Check if the user already exists
        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            flash('Username or email already exists.', 'error')
            return redirect(url_for('register'))

        # Create a new user
        new_user = User(username=username, password=hashed_password, email=email)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    # Render registration page
    return render_template('register.html')

# Dashboard route
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in first.', 'error')
        return redirect(url_for('login'))

    user_id = session['user_id']
    user = User.query.get(user_id)

    # Query the user's purchased services
    purchased_services = Purchase.query.filter_by(user_id=user_id).all()
    
    # Query suggestions for tools
    tool_suggestions = Suggestion.query.all()

    # Render the dashboard page
    return render_template('dashboard.html', user=user, purchased_services=purchased_services, tool_suggestions=tool_suggestions)

# Logout route
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

# Password validation function
def validate_password(password):
    # Check for at least one uppercase letter, one lowercase letter, one digit, and one special character
    if (re.search(r'[A-Z]', password) and 
        re.search(r'[a-z]', password) and 
        re.search(r'[0-9]', password) and 
        re.search(r'[@#$%^&+=]', password)):
        return True
    return False

# Initialize the database and run the app
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Add hardcoded cloud services
        if not CloudService.query.all():
            service1 = CloudService(name='AWS EC2', description='Amazon EC2 provides scalable cloud computing.')
            service2 = CloudService(name='Microsoft Azure', description='Microsoft Azure offers cloud computing services.')
            db.session.add_all([service1, service2])
            db.session.commit()

        # Add hardcoded purchases for the user
        if not Purchase.query.all():
            # Assuming you have a user with ID 1
            user = User.query.first()
            if user:
                purchase1 = Purchase(user_id=user.id, service_id=1)
                purchase2 = Purchase(user_id=user.id, service_id=2)
                db.session.add_all([purchase1, purchase2])
                db.session.commit()
                
        # Add hardcoded suggestions
        if not Suggestion.query.all():
            suggestions = [
                Suggestion(name='Tool A', description='A useful tool for cloud management.'),
                Suggestion(name='Tool B', description='An advanced tool for cloud security.'),
                Suggestion(name='Tool C', description='A cloud cost optimization tool.'),
                Suggestion(name='Tool D', description='A tool for monitoring cloud resources.'),
                Suggestion(name='Tool E', description='A tool for cloud resource management.')
            ]
            db.session.add_all(suggestions)
            db.session.commit()
        
    app.run(debug=True)
