# JWT-Authentication-Messaging-Application

## Index

1. [Overview](#overview)
2. [Features](#features)
3. [Technology Stack](#technology-stack)
4. [Setup and Installation](#setup-and-installation)
5. [Code Walkthrough](#code-walkthrough)
    - [JWT Authentication](#jwt-authentication)
    - [AES Encryption and Decryption](#aes-encryption-and-decryption)
    - [Routes](#routes)
6. [Testing the Application](#testing-the-application)
    - [Using Postman](#using-postman)
    - [Using cURL](#using-curl)
7. [Notes on Authorization Token](#notes-on-authorization-token)

---

## Overview

This is a simple Flask-based messaging application that allows users to:
- Register and log in securely.
- Send and receive encrypted messages.
- Authenticate using JSON Web Tokens (JWT).

The application ensures security through password hashing, token-based authentication, and AES encryption for message content.

---

## Features

- **User Registration**: Users can create accounts with hashed passwords.
- **User Login**: Secure authentication with JWT tokens.
- **Send Encrypted Messages**: Messages are encrypted using AES before storage.
- **Retrieve Decrypted Messages**: Recipients can retrieve and decrypt messages.
- **Logging**: Logs key activities such as user registration, login attempts, and message actions.

---

## Technology Stack

- **Backend**: Flask
- **Encryption**: Python's `cryptography` library (AES)
- **Authentication**: JWT (`pyjwt` library)
- **Password Hashing**: Werkzeug's security utilities
- **Logging**: Python's built-in `logging` module

---

## Setup and Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/eng-MohamedFayed/JWT-Authentication-Messaging-Application
    cd JWT-Authentication-Messaging-Application
    ```

2. Install the required dependencies:
    ```bash
    pip install flask pyjwt cryptography werkzeug
    ```

3. Run the application:
    ```bash
    python messaging.py
    ```

4. Access the application at `http://127.0.0.1:5000`.

---

## Code Walkthrough

### JWT Authentication

- **Token Generation**: The `generate_token` function creates a JWT containing the username and expiration time.
- **Token Validation**: The `validate_token` function checks the token’s validity and ensures it is active.

### AES Encryption and Decryption

- **Encryption**: Messages are encrypted using AES in CBC mode with a random IV. Padding is applied to ensure the message fits block size requirements.
- **Decryption**: Messages are decrypted using the stored ciphertext and IV, and padding is removed.

### Routes

1. **`/register`**:
    - Registers a new user with a hashed password.
    - Logs the registration event.

2. **`/login`**:
    - Authenticates users with their credentials.
    - Returns a JWT token for valid credentials.
    - Logs login attempts.

3. **`/send-message`**:
    - Requires a valid JWT in the `Authorization` header.
    - Encrypts the message and stores it with the recipient’s username.
    - Logs the message-sending event.

4. **`/retrieve-messages`**:
    - Requires a valid JWT in the `Authorization` header.
    - Decrypts and returns all messages sent to the authenticated user.
    - Logs the retrieval event.

---

## Testing the Application

### Using Postman

1. **Register Users**:
    - Endpoint: `POST /register`
    - Body (JSON):
        ```json
        {
            "username": "user1",
            "password": "password123"
        }
        ```

2. **Login Users**:
    - Endpoint: `POST /login`
    - Body (JSON):
        ```json
        {
            "username": "user1",
            "password": "password123"
        }
        ```
    - Note the token in the response.

3. **Send a Message**:
    - Endpoint: `POST /send-message`
    - Headers:
        ```
        Authorization: <token>
        ```
    - Body (JSON):
        ```json
        {
            "message": "Hello, user2!",
            "recipient": "user2"
        }
        ```

4. **Retrieve Messages**:
    - Endpoint: `GET /retrieve-messages`
    - Headers:
        ```
        Authorization: <token>
        ```

### Using cURL

1. **Register Users**:
    ```bash
    curl -X POST http://127.0.0.1:5000/register -H "Content-Type: application/json" -d '{"username": "user1", "password": "password123"}'
    ```

2. **Login Users**:
    ```bash
    curl -X POST http://127.0.0.1:5000/login -H "Content-Type: application/json" -d '{"username": "user1", "password": "password123"}'
    ```
    - Save the token from the response.

3. **Send a Message**:
    ```bash
    curl -X POST http://127.0.0.1:5000/send-message -H "Content-Type: application/json" -H "Authorization: <token>" -d '{"message": "Hello, user2!", "recipient": "user2"}'
    ```

4. **Retrieve Messages**:
    ```bash
    curl -X GET http://127.0.0.1:5000/retrieve-messages -H "Authorization: <token>"
    ```

---

## Notes on Authorization Token

- Tokens are required in the `Authorization` header when you are sending messages or retrieving the messages sent to you.
- Format:
    ```
    Authorization: <token>
    ```
- Example:
    ```
    Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImZheWVkIiwiZXhwIjoxNzM0MjkyODY3fQ.E2PlJzRMooVazixeGBfuGIwXP9iMQ46AsB0hj0ZREto
    ```
