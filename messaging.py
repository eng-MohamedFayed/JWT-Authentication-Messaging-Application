from flask import Flask, request, jsonify
import jwt
import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from werkzeug.security import generate_password_hash, check_password_hash
import os
import logging

"""
This is a simple messaging application that allows users to send and receive encrypted messages.
The application uses JSON Web Tokens (JWTs) for authentication and authorization.
The application uses the Flask web framework and the cryptography library for encryption.
The application uses the Werkzeug library for password hashing.
"""

# Flask app setup
app = Flask(__name__)

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("app.log"),  # Logs to a file named app.log
        logging.StreamHandler()          # Logs to the console
    ]
)

# Secret key for JWT
token_secret = "supersecretkey"  # Replace with a more secure secret key

def generate_key():
    return os.urandom(32)  # 256-bit AES key

# Encryption/Decryption key (should be stored securely, e.g., in environment variables)
encryption_key = generate_key()

# Simulated in-memory storage for users, messages, and tokens
users = {}  # {username: hashed_password}
messages = []  # {username: sender, encrypted: {ciphertext, iv}, recipient}
active_tokens = {}  # {username: {token, exp}}

# JWT Utility Functions
def generate_token(username):
    payload = {
        "username": username,
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)  # Token expires in 1 hour
    }
    return jwt.encode(payload, token_secret, algorithm="HS256")

def validate_token(token):
    try:
        payload = jwt.decode(token, token_secret, algorithms=["HS256"])
        username = payload.get("username")
        if username not in active_tokens or active_tokens[username]["token"] != token:
            return {"error": "Invalid token"}
        return payload
    except jwt.ExpiredSignatureError:
        return {"error": "Token has expired"}
    except jwt.InvalidTokenError:
        return {"error": "Invalid token"}

# AES Encryption/Decryption Functions for the messages
def encrypt_message(message):
    iv = os.urandom(16)  # Generate a random 16-byte IV as AES block size is 128 bits
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return {"ciphertext": ciphertext, "iv": iv}  # Return both ciphertext and IV

def decrypt_message(ciphertext, iv):
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return unpadded_data.decode()

# Routes
@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    if username in users:
        return jsonify({"error": "User already exists"}), 400

    hashed_password = generate_password_hash(password)
    users[username] = hashed_password

    logging.info(f"User registered: {username}")
    return jsonify({"message": "User registered successfully"}), 201

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    stored_password = users.get(username)
    if not stored_password or not check_password_hash(stored_password, password):
        logging.warning(f"Failed login attempt for user: {username}")
        return jsonify({"error": "Invalid username or password"}), 401

    # Check if the user already has a valid token
    if username in active_tokens:
        token_info = active_tokens[username]
        if token_info["exp"] > datetime.datetime.now(datetime.timezone.utc):
            logging.info(f"User logged in: {username}")
            return jsonify({"token": token_info["token"]})

    # Generate a new token
    token = generate_token(username)
    exp_time = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
    active_tokens[username] = {"token": token, "exp": exp_time}

    logging.info(f"User logged in: {username}")
    return jsonify({"token": token})

@app.route("/send-message", methods=["POST"])
def send_message():
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"error": "Authorization token required"}), 401

    validation_result = validate_token(token)
    if "error" in validation_result:
        return jsonify(validation_result), 401

    username = validation_result["username"]
    data = request.json
    message = data.get("message")
    recipient = data.get("recipient")

    if recipient not in users:
        return jsonify({"error": "Recipient does not exist"}), 400
    if not recipient:
        return jsonify({"error": "Recipient is required"}), 400
    if not message:
        return jsonify({"error": "Message is required"}), 400

    encrypted_data = encrypt_message(message)
    messages.append({"username": username, "encrypted": encrypted_data, "recipient": recipient})

    logging.info(f"Message sent from {username} to {recipient}")
    return jsonify({"message": "Message sent successfully"})

@app.route("/retrieve-messages", methods=["GET"])
def retrieve_messages():
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"error": "Authorization token required"}), 401

    validation_result = validate_token(token)
    if "error" in validation_result:
        return jsonify(validation_result), 401

    username = validation_result["username"]

    user_messages = [
        {
            "sender": msg["username"],
            "message": decrypt_message(msg["encrypted"]["ciphertext"], msg["encrypted"]["iv"])
        }
        for msg in messages if msg['recipient'] == username
    ]

    logging.info(f"Messages retrieved for user: {username}")
    return jsonify({"messages": user_messages})

if __name__ == "__main__":
    app.run(debug=True)
