#Hriday Bhavsar (hdb0075)
from flask import Flask, jsonify, request
import sqlite3
import datetime
import jwt
import base64
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

DATABASE = 'totally_not_my_privateKeys.db'
JWT_ALGORITHM = 'RS256'

def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS keys (
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT NOT NULL,
                exp INTEGER NOT NULL
            )
        ''')
        conn.commit()

def generate_rsa_key():
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    private_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    return private_key

def insert_key(private_key, exp):
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (private_key, exp))
        conn.commit()

def get_key(expired=False):
    current_time = int(datetime.datetime.now(datetime.UTC).timestamp())
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        if expired:
            cursor.execute('SELECT key FROM keys WHERE exp <= ? ORDER BY exp LIMIT 1', (current_time,))
        else:
            cursor.execute('SELECT key FROM keys WHERE exp > ? ORDER BY exp LIMIT 1', (current_time,))
        row = cursor.fetchone()
        return row[0] if row else None

@app.route('/auth', methods=['POST'])
def auth():
    expired_param = request.args.get('expired')
    private_key_pem = get_key(expired=bool(expired_param))
    if not private_key_pem:
        return jsonify({"error": "No key found"}), 500

    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None,
        backend=default_backend()
    )

    payload = {
        'iat': datetime.datetime.utcnow(),
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=5),
        'nbf': datetime.datetime.utcnow()
    }
    token = jwt.encode(payload, private_key_pem, algorithm=JWT_ALGORITHM, headers={'kid': '1'})
    return jsonify({'jwt': token})

@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    current_time = int(datetime.datetime.now(datetime.UTC).timestamp())
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT key, kid FROM keys WHERE exp > ?', (current_time,))
        rows = cursor.fetchall()

    keys = []
    for row in rows:
        private_key_pem = row[0]
        kid = row[1]
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()
        e = public_numbers.e
        n = public_numbers.n

        key_data = {
            'kty': 'RSA',
            'use': 'sig',
            'kid': str(kid),
            'n': base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip('='),
            'e': base64.urlsafe_b64encode(e.to_bytes((e.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip('='),
            'alg': JWT_ALGORITHM
        }
        keys.append(key_data)

    return jsonify({'keys': keys})

if __name__ == '__main__':
    init_db()
    # Insert one expired key
    expired_key = generate_rsa_key()
    expired_time = int((datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=1)).timestamp())
    insert_key(expired_key, expired_time)

    # Insert one valid key
    valid_key = generate_rsa_key()
    valid_time = int((datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)).timestamp())
    insert_key(valid_key, valid_time)

    app.run(host='0.0.0.0', port=8080, debug=True)
