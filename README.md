# JWKS Server Project

## Overview
This project implements a JSON Web Key Set (JWKS) server with SQLite-backed storage. It is designed to securely store RSA private keys, prevent SQL injection, and serve JWTs signed with valid or expired keys as needed.

## Features
- Stores RSA private keys in a SQLite database (`totally_not_my_privateKeys.db`).
- Automatically generates and stores:
  - At least one key that expires immediately (expired key).
  - At least one key valid for one hour.
- Provides two main endpoints:
  - `POST /auth`: Issues JWT signed by a valid or expired private key based on the query parameter.
  - `GET /.well-known/jwks.json`: Serves public keys in JWKS format.
- Secure database queries using query parameters to prevent SQL injection.
- Fully tested using `pytest` with over **70% coverage**.

## Endpoints

### `POST /auth`
- **Description:** Issues a JWT.
- **Query Parameters:**
  - `expired` (optional): If present, issues JWT signed with an expired key.
- **Response:**
```json
{
  "jwt": "<signed_token>"
}
```

---

### `GET /.well-known/jwks.json`
- **Description:** Returns all valid (non-expired) public keys in JWKS format.
- **Response:**
```json
{
  "keys": [ ... ]
}
```

---

## How to Run

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Run the Flask server:

```bash
python3 app.py
```

Server runs on:

```
http://127.0.0.1:8080
```

---

## Running Tests

Run:

```bash
pytest --cov=app > coverage.txt
```

Coverage report will be generated in `coverage.txt`.

---

## Files

| File                       | Description                                               |
|---------------------------|-----------------------------------------------------------|
| `app.py`                   | Main Flask application and logic                          |
| `totally_not_my_privateKeys.db` | SQLite DB containing RSA private keys                  |
| `test_app.py`              | Test suite for `/auth` and `/jwks.json` endpoints          |
| `requirements.txt`        | Dependencies (Flask, PyJWT, cryptography, pytest, etc.)    |
| `coverage.txt`            | Test coverage report                                      |

---

## Security Considerations
- Secure SQL queries using query parameters to avoid SQL injection.
- Private keys stored securely in serialized PEM format.
- JWTs signed using RSA (RS256 algorithm).

---

## Author
Hriday Bhavsar

