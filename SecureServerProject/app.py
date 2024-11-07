from flask import Flask, render_template, request, redirect, session, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.Cipher import AES
import os
from base64 import b64encode, b64decode
import bcrypt
import math
import random
import smtplib
import mysql.connector
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from binascii import unhexlify

conn = mysql.connector.connect(host="localhost",username="root",password="",database="Information_Security_Lab")
cursor = conn.cursor(dictionary=True)

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
# def send_otp():
#     global otp_generated
#     email = request.form['email']
#     otp_generated = generate_otp()

#     # Compose the message
#     otp_message = otp_generated + " is your OTP."

#     # Sending the OTP to the email (without try-except)
#     s = smtplib.SMTP('smtp.gmail.com', 587)
#     s.starttls()
#     s.login("guptatanmay921@gmail.com", "tvok tuew ntwm adel")
#     s.sendmail("guptatanmay921@gmail.com", email, otp_message)
#     s.quit()

#     return "OTP sent successfully!"

def send_otp():
    global otp_generated

    # Check if the user is logged in and has an email in the session
    if 'username' in session:
        username = session['username']

        # Query the database to get the user's email
        cursor.execute("SELECT email FROM users WHERE username=%s", (username,))
        user = cursor.fetchone()

        # Ensure the user exists and has an email
        if user is not None and 'email' in user:
            email = user['email']  # Get the email from the database
            
            # Generate the OTP
            otp_generated = generate_otp()

            subject = "Your OTP for login"
            # Compose the OTP message
            otp_message = f"{otp_generated} is your OTP."

            # Sending the OTP via email
            s = smtplib.SMTP('smtp.gmail.com', 587)
            s.starttls()
            s.login("guptatanmay921@gmail.com", "tvok tuew ntwm adel")
            s.sendmail("guptatanmay921@gmail.com", email, otp_message)
            s.quit()

            return "OTP sent successfully!"
        else:
            flash('User not found or no email available!')
            return redirect(url_for('login'))
    else:
        # If the user is not logged in, redirect to the login page
        return redirect(url_for('login'))


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
    send_otp()
    return render_template('verify_otp.html')

# @app.route('/verify_otp', methods=['GET', 'POST'])
# def verify_otp():
#     if request.method == 'POST':
#         try:
#             user_otp = request.form['otp']
#             if user_otp == otp_generated:
#                 flash("OTP verified successfully!")
#                 return redirect(url_for('dashboard'))
#             else:
#                 flash("Invalid OTP! Please check your OTP again.")
#         except Exception as e:
#             flash(f"An error occurred: {str(e)}")  # Capture any exception that occurs
#             return redirect(url_for('verify_otp'))

#     # Automatically send OTP when the page loads
    


# AES encryption settings
aes_key_hex = "0123456789ABCDEF0123456789ABCDEF"
aes_key = unhexlify(aes_key_hex)

aes_block_size = AES.block_size

# def encrypt_aes(msg):
#     # Create a new AES cipher object in CBC mode
#     cipher = AES.new(aes_key, AES.MODE_CBC)
#     # Pad the message to ensure it is a multiple of the block size
#     padded_msg = pad(msg.encode('utf-8'), aes_block_size)
#     # Encrypt the padded message
#     ciphertext = cipher.encrypt(padded_msg)
#     # Return the IV and ciphertext
#     return cipher.iv, ciphertext

# def decrypt_aes(iv, ciphertext):
#     # Create a new AES cipher object with the given IV
#     cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
#     # Decrypt the ciphertext
#     padded_plaintext = cipher.decrypt(ciphertext)
#     # Unpad the plaintext to retrieve the original message
#     plaintext = unpad(padded_plaintext, aes_block_size).decode('utf-8')
#     return plaintext

def encrypt_aes(msg):
    cipher = AES.new(aes_key, AES.MODE_CBC)
    padded_msg = pad(msg.encode('utf-8'), aes_block_size)
    ciphertext = cipher.encrypt(padded_msg)
    iv = b64encode(cipher.iv).decode('utf-8')  # Convert IV to base64
    ciphertext = b64encode(ciphertext).decode('utf-8')  # Convert ciphertext to base64
    return iv, ciphertext

def decrypt_aes(iv, ciphertext):
    iv = b64decode(iv)  # Decode base64 IV
    ciphertext = b64decode(ciphertext)  # Decode base64 ciphertext
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, aes_block_size).decode('utf-8')
    return plaintext

# Route to render home
@app.route('/')
def home():
    return render_template('register.html')

# User registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get data from form
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        profile_info = request.form['info']

        # Check if username or email already exists in the database
        cursor.execute("SELECT * FROM users WHERE username=%s OR email=%s", (username, email))
        user_exists = cursor.fetchone()
        
        if user_exists:
            flash("Username or email already exists. Please choose another one.")
            return redirect(url_for('register'))

        # Hash the password before storing
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        iv,user_info = encrypt_aes(profile_info)
        session['iv'] = iv
        # Insert user data into the database
        cursor.execute("INSERT INTO users (username, email, hashed_password, encrypted_info) VALUES (%s, %s, %s, %s)", 
                       (username, email, hashed_password, user_info))
        conn.commit()

        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))

    return render_template('register.html')

# User login route
@app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']

#         user = users_db.get(username)

#         if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
#             session['username'] = username
#             # After successful login, redirect to the OTP verification page
#             otp_generated = generate_otp()

#             # Redirect to the verify OTP page
#             return redirect(url_for('verify_otp'))
#         else:
#             flash('Invalid credentials!')

#     return render_template('login.html')

def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Query to retrieve the hashed password from the database
        cursor.execute("SELECT hashed_password FROM users WHERE username=%s", (username,))
        user = cursor.fetchone()
        print(type(user))

        # Check if the user exists (i.e., user is not None)
        if user is not None:
            # Access the hashed_password
            hashed_password = user['hashed_password']  # type: ignore # Access the first element if user is a tuple

            # Check if the hashed_password is in bytes
            if isinstance(hashed_password, str):
                hashed_password = hashed_password.encode('utf-8')  # Convert to bytes if it's a string

            # Verify the password
            if bcrypt.checkpw(password.encode('utf-8'), hashed_password): # type: ignore
                session['username'] = username
                
                # Generate OTP after successful login
                otp_generated = generate_otp()

                # Redirect to the OTP verification page
                return redirect(url_for('verify_otp'))
            else:
                flash('Invalid credentials!')
        else:
            flash('Invalid credentials!')

    return render_template('login.html')



# User dashboard route
@app.route('/dashboard')
# def dashboard():
#     if 'username' in session:
#         username = session['username']
#         # Decrypt user data for display
#         user_info = decrypt_data(users_db[username]['profile_info'])
#         return render_template('dashboard.html', username=username, user_info=user_info)
#     else:
#         return redirect(url_for('home'))
def dashboard():
    if 'username' in session:
        username = session['username']
        # username = 'tanmay'
        # Query to retrieve the user profile info from the database
        cursor.execute("SELECT encrypted_info FROM users WHERE username=%s", (username,))
        user = cursor.fetchone()

        # Check if the user exists
        if user is not None:
            # Access and decrypt the user's profile information
            iv = session.get('iv')
            encrypted_info = user['encrypted_info']  # Assuming 'profile_info' is the column name
            decrypted_info = decrypt_aes(iv,encrypted_info)  # Decrypt the profile_info

            # Render the dashboard page with decrypted user information
            return render_template('dashboard.html', username='tanmay', user_info=decrypted_info)
        else:
            flash('User not found!')
            return redirect(url_for('home'))
    else:
        # If the user is not logged in, redirect to the home page
        return redirect(url_for('home'))


# Logout route
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Logged out successfully!')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
