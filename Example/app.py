from flask import Flask, render_template, request, jsonify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import os
import base64
from pymongo import MongoClient

app = Flask(__name__)

# MongoDB connection
client = MongoClient('mongodb://localhost:27017/')  # Connect to MongoDB
db = client['encrypted_data_db']  # Database name
collection = db['encrypted_features']  # Collection name

# Generate RSA keys
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/user1', methods=['POST'])
def user1():
    global encrypted_features, encrypted_result, rsa_encrypted_aes_key, aes_key, iv

    # User-1 inputs 5 features
    features = [request.form[f'feature{i}'] for i in range(1, 6)]
    result = "Great"

    # Generate AES key and IV
    aes_key = os.urandom(32)  # 256-bit AES key
    iv = os.urandom(16)  # 128-bit IV

    # Encrypt features using AES
    encrypted_features = []
    for feature in features:
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_feature = encryptor.update(feature.encode()) + encryptor.finalize()
        encrypted_features.append(base64.b64encode(encrypted_feature).decode('utf-8'))  # Encode as Base64

    # Encrypt result using AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_result = encryptor.update(result.encode()) + encryptor.finalize()
    encrypted_result = base64.b64encode(encrypted_result).decode('utf-8')  # Encode as Base64

    # Encrypt AES key using RSA
    rsa_encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    rsa_encrypted_aes_key = base64.b64encode(rsa_encrypted_aes_key).decode('utf-8')  # Encode as Base64

    # Store encrypted data in MongoDB
    encrypted_data = {
        'encrypted_features': encrypted_features,  # Already Base64 encoded
        'encrypted_result': encrypted_result,  # Already Base64 encoded
        'rsa_encrypted_aes_key': rsa_encrypted_aes_key,  # Already Base64 encoded
        'iv': base64.b64encode(iv).decode('utf-8')  # Encode IV as Base64
    }
    collection.insert_one(encrypted_data)

    return jsonify({
        'encrypted_features': encrypted_features,  # Already Base64 encoded
        'encrypted_result': encrypted_result,  # Already Base64 encoded
        'aes_key': base64.b64encode(aes_key).decode('utf-8'),  # Encode AES key in Base64
        'rsa_encrypted_aes_key': rsa_encrypted_aes_key,  # Already Base64 encoded
        'iv': base64.b64encode(iv).decode('utf-8')  # Share the IV
    })

@app.route('/user2', methods=['GET', 'POST'])
def user2():
    if request.method == 'POST':
        action = request.form['action']

        if action == 'view_encrypted_data':
            # Fetch encrypted data from MongoDB
            encrypted_data = collection.find_one()
            return jsonify({
                'encrypted_features': encrypted_data['encrypted_features'],
                'encrypted_result': encrypted_data['encrypted_result'],
                'iv': encrypted_data['iv']
            })

        elif action == 'view_rsa_encrypted_key':
            # Fetch RSA encrypted AES key from MongoDB
            encrypted_data = collection.find_one()
            return jsonify({
                'rsa_encrypted_aes_key': encrypted_data['rsa_encrypted_aes_key']
            })

        elif action == 'decrypt_and_view_aes_key':
            try:
                # Fetch encrypted data from MongoDB
                encrypted_data = collection.find_one()

                # Ensure proper Base64 padding for RSA encrypted AES key
                rsa_encrypted_aes_key_b64 = encrypted_data['rsa_encrypted_aes_key']
                # Add padding if necessary
                padding_length = len(rsa_encrypted_aes_key_b64) % 4
                if padding_length:
                    rsa_encrypted_aes_key_b64 += '=' * (4 - padding_length)

                # Decode the Base64 string
                rsa_encrypted_aes_key_bytes = base64.b64decode(rsa_encrypted_aes_key_b64)

                # Decrypt RSA encrypted AES key
                decrypted_aes_key = private_key.decrypt(
                    rsa_encrypted_aes_key_bytes,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                # Decode IV from Base64
                iv = base64.b64decode(encrypted_data['iv'])

                # Decrypt features using AES
                decrypted_features = []
                for ef in encrypted_data['encrypted_features']:
                    ef_bytes = base64.b64decode(ef)
                    cipher = Cipher(algorithms.AES(decrypted_aes_key), modes.CFB(iv), backend=default_backend())
                    decryptor = cipher.decryptor()
                    decrypted_feature = decryptor.update(ef_bytes) + decryptor.finalize()
                    decrypted_features.append(decrypted_feature.decode('utf-8'))

                # Decrypt result using AES
                encrypted_result_bytes = base64.b64decode(encrypted_data['encrypted_result'])
                cipher = Cipher(algorithms.AES(decrypted_aes_key), modes.CFB(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted_result = decryptor.update(encrypted_result_bytes) + decryptor.finalize()

                return jsonify({
                    'decrypted_aes_key': base64.b64encode(decrypted_aes_key).decode('utf-8'),
                    'decrypted_features': decrypted_features,
                    'decrypted_result': decrypted_result.decode('utf-8'),
                    'original_data': {
                        'features': decrypted_features,
                        'result': decrypted_result.decode('utf-8')
                    }
                })
            except Exception as e:
                return jsonify({'error': f"Decryption failed: {str(e)}"}), 500

    return render_template('user2.html')

if __name__ == '__main__':
    app.run(debug=True)