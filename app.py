from flask import Flask, render_template, request, redirect, session, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.Cipher import AES
import os
from base64 import b64encode, b64decode
import bcrypt
import math
import random
import smtplib

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Flask session encryption key

# Mock database (in-memory for demo purposes)
users_db = {}

# OTP handling
otp_generated = ""

# Function to generate OTP
def generate_otp():
    digits = "0123456789"
    otp = ""
    for i in range(6):
        otp += digits[math.floor(random.random() * 10)]
    return otp

# Route for sending OTP
@app.route('/send_otp', methods=['POST'])
def send_otp():
    global otp_generated
    email = request.form['email']
    otp_generated = generate_otp()

    # Compose the message
    otp_message = otp_generated + " is your OTP."

    # Sending the OTP to the email (without try-except)
    s = smtplib.SMTP('smtp.gmail.com', 587)
    s.starttls()
    s.login("guptatanmay921@gmail.com", "tvok tuew ntwm adel")
    s.sendmail("guptatanmay921@gmail.com", email, otp_message)
    s.quit()

    return "OTP sent successfully!"

# Route for verifying OTP
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        user_otp = request.form['otp']
        if user_otp == otp_generated:
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid OTP! Please check your OTP again.")
            return render_template('verify_otp.html')
    return render_template('verify_otp.html')

# AES encryption settings
AES_KEY = os.urandom(32)  # Replace with a secure method for real-world apps
AES_IV = os.urandom(16)

def encrypt_data(data):
    cipher = AES.new(AES_KEY, AES.MODE_CFB, AES_IV)
    return b64encode(cipher.encrypt(data.encode('utf-8'))).decode('utf-8')

def decrypt_data(enc_data):
    cipher = AES.new(AES_KEY, AES.MODE_CFB, AES_IV)
    return cipher.decrypt(b64decode(enc_data)).decode('utf-8')

# Route to render home
@app.route('/')
def home():
    return render_template('register.html')

# User registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        info = request.form['info']

        if username in users_db:
            flash('Username already exists!')
            return redirect(url_for('register'))

        # Hash the password with bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Store hashed password and encrypted user info (optional)
        users_db[username] = {
            'password': hashed_password,
            'profile_info': encrypt_data(info)
        }

        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))

    return render_template('register.html')

# User login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = users_db.get(username)

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            session['username'] = username
            # After successful login, redirect to the OTP verification page
            otp_generated = generate_otp()

            # Redirect to the verify OTP page
            return redirect(url_for('verify_otp'))
        else:
            flash('Invalid credentials!')

    return render_template('login.html')

# User dashboard route
@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        username = session['username']
        # Decrypt user data for display
        user_info = decrypt_data(users_db[username]['profile_info'])
        return render_template('dashboard.html', username=username, user_info=user_info)
    else:
        return redirect(url_for('home'))

# Logout route
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Logged out successfully!')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
