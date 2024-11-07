# from flask import Flask, render_template, request, redirect, session, url_for, flash
# from werkzeug.security import generate_password_hash, check_password_hash
# from Crypto.Cipher import AES
# import os
# from base64 import b64encode, b64decode
# import bcrypt
# import math
# import random
# import smtplib
# import mysql.connector
# from Crypto.Cipher import AES
# from Crypto.Util.Padding import pad, unpad
# from binascii import unhexlify

# conn = mysql.connector.connect(host="localhost",username="root",password="",database="Information_Security_Lab")
# cursor = conn.cursor(dictionary=True)

# app = Flask(__name__)
# app.secret_key = os.urandom(24)  # Flask session encryption key

# # Mock database (in-memory for demo purposes)
# users_db = {}

# # OTP handling
# otp_generated = ""

# # Function to generate OTP
# def generate_otp():
#     digits = "0123456789"
#     otp = ""
#     for i in range(6):
#         otp += digits[math.floor(random.random() * 10)]
#     return otp

# # Route for sending OTP
# @app.route('/send_otp', methods=['POST'])
# def send_otp():
#     global otp_generated

#     # Check if the user is logged in and has an email in the session
#     if 'username' in session:
#         username = session['username']

#         # Query the database to get the user's email
#         cursor.execute("SELECT email FROM users WHERE username=%s", (username,))
#         user = cursor.fetchone()

#         # Ensure the user exists and has an email
#         if user is not None and 'email' in user:
#             email = user['email']  # Get the email from the database
            
#             # Generate the OTP
#             otp_generated = generate_otp()

#             subject = "Your OTP for login"
#             # Compose the OTP message
#             otp_message = f"{otp_generated} is your OTP."

#             # Sending the OTP via email
#             s = smtplib.SMTP('smtp.gmail.com', 587)
#             s.starttls()
#             s.login("guptatanmay921@gmail.com", "tvok tuew ntwm adel")
#             s.sendmail("guptatanmay921@gmail.com", email, otp_message)
#             s.quit()

#             return "OTP sent successfully!"
#         else:
#             flash('User not found or no email available!')
#             return redirect(url_for('login'))
#     else:
#         # If the user is not logged in, redirect to the login page
#         return redirect(url_for('login'))


# # Route for verifying OTP
# @app.route('/verify_otp', methods=['GET', 'POST'])
# def verify_otp():
#     if request.method == 'POST':
#         user_otp = request.form['otp']
#         if user_otp == otp_generated:
#             return redirect(url_for('dashboard'))
#         else:
#             flash("Invalid OTP! Please check your OTP again.")
#             return render_template('verify_otp.html')
#     send_otp()
#     return render_template('verify_otp.html')

# # AES encryption settings
# aes_key_hex = "0123456789ABCDEF0123456789ABCDEF"
# aes_key = unhexlify(aes_key_hex)

# aes_block_size = AES.block_size

# def encrypt_aes(msg):
#     cipher = AES.new(aes_key, AES.MODE_CBC)
#     padded_msg = pad(msg.encode('utf-8'), aes_block_size)
#     ciphertext = cipher.encrypt(padded_msg)
#     iv = b64encode(cipher.iv).decode('utf-8')  # Convert IV to base64
#     ciphertext = b64encode(ciphertext).decode('utf-8')  # Convert ciphertext to base64
#     return iv, ciphertext

# def decrypt_aes(iv, ciphertext):
#     iv = b64decode(iv)  # Decode base64 IV
#     ciphertext = b64decode(ciphertext)  # Decode base64 ciphertext
#     cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
#     padded_plaintext = cipher.decrypt(ciphertext)
#     plaintext = unpad(padded_plaintext, aes_block_size).decode('utf-8')
#     return plaintext

# # Route to render home
# @app.route('/')
# def home():
#     return render_template('register.html')

# # User registration route
# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     if request.method == 'POST':
#         # Get data from form
#         username = request.form['username']
#         email = request.form['email']
#         password = request.form['password']
#         profile_info = request.form['info']

#         # Check if username or email already exists in the database
#         cursor.execute("SELECT * FROM users WHERE username=%s OR email=%s", (username, email))
#         user_exists = cursor.fetchone()
        
#         if user_exists:
#             flash("Username or email already exists. Please choose another one.")
#             return redirect(url_for('register'))

#         # Hash the password before storing
#         hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
#         iv,user_info = encrypt_aes(profile_info)
#         session['iv'] = iv
#         # Insert user data into the database
#         cursor.execute("INSERT INTO users (username, email, hashed_password, encrypted_info) VALUES (%s, %s, %s, %s)", 
#                        (username, email, hashed_password, user_info))
#         conn.commit()

#         flash('Registration successful! Please log in.')
#         return redirect(url_for('login'))

#     return render_template('register.html')

# # User login route
# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']

#         # Query to retrieve the hashed password from the database
#         cursor.execute("SELECT hashed_password FROM users WHERE username=%s", (username,))
#         user = cursor.fetchone()
#         print(type(user))

#         # Check if the user exists (i.e., user is not None)
#         if user is not None:
#             # Access the hashed_password
#             hashed_password = user['hashed_password']  # type: ignore # Access the first element if user is a tuple

#             # Check if the hashed_password is in bytes
#             if isinstance(hashed_password, str):
#                 hashed_password = hashed_password.encode('utf-8')  # Convert to bytes if it's a string

#             # Verify the password
#             if bcrypt.checkpw(password.encode('utf-8'), hashed_password): # type: ignore
#                 session['username'] = username
                
#                 # Generate OTP after successful login
#                 otp_generated = generate_otp()

#                 # Redirect to the OTP verification page
#                 return redirect(url_for('verify_otp'))
#             else:
#                 flash('Invalid credentials!')
#         else:
#             flash('Invalid credentials!')

#     return render_template('login.html')

# # User dashboard route
# @app.route('/dashboard')
# def dashboard():
#     if 'username' in session:
#         username = session['username']
#         # username = 'tanmay'
#         # Query to retrieve the user profile info from the database
#         cursor.execute("SELECT encrypted_info FROM users WHERE username=%s", (username,))
#         user = cursor.fetchone()

#         # Check if the user exists
#         if user is not None:
#             # Access and decrypt the user's profile information
#             iv = session.get('iv')
#             encrypted_info = user['encrypted_info']  # Assuming 'profile_info' is the column name
#             decrypted_info = decrypt_aes(iv,encrypted_info)  # Decrypt the profile_info

#             # Render the dashboard page with decrypted user information
#             return render_template('dashboard.html', username='tanmay', user_info=decrypted_info)
#         else:
#             flash('User not found!')
#             return redirect(url_for('home'))
#     else:
#         # If the user is not logged in, redirect to the home page
#         return redirect(url_for('home'))


# # Logout route
# @app.route('/logout')
# def logout():
#     session.pop('username', None)
#     flash('Logged out successfully!')
#     return redirect(url_for('home'))

# if __name__ == '__main__':
#     app.run(debug=True)

from flask import Flask, render_template, request, redirect, session, url_for, flash, send_from_directory
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
from Crypto.Random import get_random_bytes
from werkzeug.utils import secure_filename
from datetime import timedelta

conn = mysql.connector.connect(host="localhost",username="root",password="",database="Information_Security_Lab")
cursor = conn.cursor(dictionary=True)

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Flask session encryption key

# Mock database (in-memory for demo purposes)
users_db = {}

# OTP handling
otp_generated = ""

# Upload settings
UPLOAD_FOLDER = 'uploads'
ENCRYPTED_FOLDER = 'encrypted'
DECRYPTED_FOLDER = 'decrypted'
KEY = get_random_bytes(16)  # Use a fixed key for simplicity, or generate per-user

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)  # Lock duration

# Email settings
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
EMAIL_ADDRESS = 'guptatanmay921@gmail.com'
EMAIL_PASSWORD = 'tvok tuew ntwm adel'

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

# AES encryption settings
aes_key_hex = "0123456789ABCDEF0123456789ABCDEF"
aes_key = unhexlify(aes_key_hex)

aes_block_size = AES.block_size

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
    return redirect(url_for('login'))

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
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Initialize attempts in session if not set
        if 'login_attempts' not in session:
            session['login_attempts'] = 0

        # Check if the account is locked
        if session.get('account_locked'):
            return "Account locked due to too many failed attempts. Please try again later."

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
                # Increment login attempts
                session['login_attempts'] += 1
                if session['login_attempts'] >= 3:
                    session['account_locked'] = True
                    cursor.execute("SELECT email FROM users WHERE username=%s", (username,))
                    user_email = cursor.fetchone()['email']
                    send_security_email(username, user_email)  # Send email on account lock
                    return "Account locked due to too many failed attempts. Check your email."

                return "Invalid credentials. Try again."
        else:
            # Increment login attempts
            session['login_attempts'] += 1
            if session['login_attempts'] >= 3:
                session['account_locked'] = True
                send_security_email(username)  # Send email on account lock
                return "Account locked due to too many failed attempts. Check your email."

            return "Invalid credentials. Try again."
    return render_template('login.html')

# User dashboard route
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    user_upload_folder = os.path.join(UPLOAD_FOLDER, session['username'])
    uploaded_files = os.listdir(user_upload_folder)
    return render_template('dashboard1.html', files=uploaded_files)

# Upload page with both GET and POST methods
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        if 'file' not in request.files:
            print("No file part in the request")
            return "No file part in the request", 400

        file = request.files['file']
        if not file or file.filename == '':
            print("No selected file or filename is empty")
            return "No selected file", 400

        # Secure the filename
        filename = secure_filename(file.filename)
        if filename == '':
            print("Filename could not be secured and is empty")
            return "Invalid filename", 400

        # Save file to user-specific folder
        user_upload_folder = os.path.join(UPLOAD_FOLDER, session['username'])
        file_path = os.path.join(user_upload_folder, filename)
        file.save(file_path)
        
        # Encrypt the file
        encrypted_file_path, key, iv, ciphertext = encrypt_file(file_path, KEY)
        
        return redirect(url_for('dashboard'))
    
    return render_template('upload.html')

# Function to encrypt a file
def encrypt_file(file_path, key):
    cipher = AES.new(key, AES.MODE_CBC)
    with open(file_path, 'rb') as file:
        file_data = file.read()
    padded_data = pad(file_data, AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    encrypted_file_path = os.path.join(ENCRYPTED_FOLDER, os.path.basename(file_path) + '.enc')
    with open(encrypted_file_path, 'wb') as enc_file:
        enc_file.write(cipher.iv)
        enc_file.write(ciphertext)
    return encrypted_file_path, key.hex(), cipher.iv.hex(), ciphertext.hex()  # Return key, IV, and ciphertext

# Function to decrypt a file
def decrypt_file(file_path, key):
    with open(file_path, 'rb') as enc_file:
        iv_and_ciphertext = enc_file.read()
    iv = iv_and_ciphertext[:AES.block_size]
    ciphertext = iv_and_ciphertext[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)
    decrypted_file_path = os.path.join(DECRYPTED_FOLDER, os.path.basename(file_path).replace('.enc', ''))
    with open(decrypted_file_path, 'wb') as dec_file:
        dec_file.write(plaintext)
    return decrypted_file_path

# Download encrypted file
@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory(ENCRYPTED_FOLDER, filename)

# Decrypt and download the file
@app.route('/decrypt/<filename>')
def decrypt_and_download(filename):
    encrypted_file_path = os.path.join(ENCRYPTED_FOLDER, filename)
    decrypted_file_path = decrypt_file(encrypted_file_path, KEY)
    return send_from_directory(DECRYPTED_FOLDER, os.path.basename(decrypted_file_path))

@app.route('/encrypt_and_display', methods=['POST'])
def encrypt_and_display():
    if 'username' not in session:
        return redirect(url_for('login'))

    if 'file' not in request.files:
        return "No file part in the request", 400

    file = request.files['file']
    if file.filename == '':
        return "No selected file", 400

    # Secure the filename and save to user-specific folder
    filename = secure_filename(file.filename)
    user_upload_folder = os.path.join(UPLOAD_FOLDER, session['username'])
    os.makedirs(user_upload_folder, exist_ok=True)
    file_path = os.path.join(user_upload_folder, filename)
    file.save(file_path)

    # Encrypt the file and get the encryption details
    encrypted_file_path, key, iv, ciphertext = encrypt_file(file_path, KEY)

    # Render the encryption details on a results page
    return render_template('encryption_result.html', key=key, iv=iv, ciphertext=ciphertext)

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def send_security_email(username, user_email):
    msg = MIMEMultipart()
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = user_email  # Use the user's registered email
    msg['Subject'] = "Security Alert: Login Attempt Detected"

    body = f"""
    Dear {username},

    We detected multiple failed login attempts on your account. As a precaution, we have temporarily locked your account.

    If this was not you, please consider resetting your password and taking additional security measures.

    Sincerely,
    Security Team
    """
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.sendmail(EMAIL_ADDRESS, user_email, msg.as_string())
        server.quit()
        print("Security email sent successfully.")
    except Exception as e:
        print(f"Error sending email: {e}")

# Logout the user
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)