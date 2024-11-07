from flask import Flask, request, send_from_directory, render_template, redirect, url_for, session
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from werkzeug.utils import secure_filename
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import timedelta





# Email settings
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
EMAIL_ADDRESS = 'guptatanmay921@gmail.com'
EMAIL_PASSWORD = 'tanmay123'

# s = smtplib.SMTP('smtp.gmail.com', 587)
#             s.starttls()
#             s.login("guptatanmay921@gmail.com", "tvok tuew ntwm adel")
#             s.sendmail("guptatanmay921@gmail.com", email, otp_message)

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Secret key for session management
UPLOAD_FOLDER = 'uploads'
ENCRYPTED_FOLDER = 'encrypted'
DECRYPTED_FOLDER = 'decrypted'
KEY = get_random_bytes(16)  # Use a fixed key for simplicity, or generate per-user

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)  # Lock duration

# Reset login attempts on each new session
@app.before_request
def make_session_permanent():
    session.permanent = True

# Ensure directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)
os.makedirs(DECRYPTED_FOLDER, exist_ok=True)

# Function to encrypt a file
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

@app.route('/')
def home():
    return redirect(url_for('dashboard'))

# Simple user login (for demonstration purposes)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Initialize attempts in session if not set
        if 'login_attempts' not in session:
            session['login_attempts'] = 0

        # Check if the account is locked
        if session.get('account_locked'):
            return "Account locked due to too many failed attempts. Please try again later."

        # Dummy credentials check (replace with actual authentication)
        if username == 'tanmay' and password == 'correct_password':
            session['username'] = username
            session.pop('login_attempts', None)  # Reset login attempts on success
            return redirect(url_for('dashboard'))
        else:
            # Increment login attempts
            session['login_attempts'] += 1
            if session['login_attempts'] >= 3:
                session['account_locked'] = True
                send_security_email(username)  # Send email on account lock
                return "Account locked due to too many failed attempts. Check your email."

            return "Invalid credentials. Try again."
    return render_template('login.html')

# User dashboard to show uploaded files
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
        encrypted_file_path = encrypt_file(file_path, KEY)
        
        return redirect(url_for('dashboard'))
    
    return render_template('upload.html')



def send_security_email(username):
    msg = MIMEMultipart()
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = 'tanmaygupta1706@gmail.com'  # Replace with the registered user’s email
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
        server.sendmail(EMAIL_ADDRESS, 'Tanmaygupta1706@gmail.com', msg.as_string())
        server.quit()
        print("Security email sent successfully.")
    except Exception as e:
        print(f"Error sending email: {e}")

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

# Logout the user
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
