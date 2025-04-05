from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import base64
import joblib
import numpy as np
import os
import dotenv
import sys
import logging

# Load environment variables
dotenv.load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Disable pymongo debug logs
logging.getLogger("pymongo").setLevel(logging.WARNING)

app = Flask(__name__)
CORS(app)

# Load ML Model
MODEL_PATH = r"C:\Users\naras\OneDrive\Documents\Desktop\Network Intrution detection system\backend\models\KNeighborsClassifier.joblib"

if not os.path.exists(MODEL_PATH):
    logger.error(f"❌ Error: Model file not found at {MODEL_PATH}")
    sys.exit(1)

try:
    model = joblib.load(MODEL_PATH)
    logger.info("✅ Model loaded successfully!")
except Exception as e:
    logger.error(f"❌ Error loading model: {e}")
    sys.exit(1)

# MongoDB Setup
try:
    client = MongoClient(
        'mongodb://localhost:27017/',
        heartbeatFrequencyMS=10000,
        maxPoolSize=50,
        connectTimeoutMS=30000,
        socketTimeoutMS=30000
    )
    db = client['nids']
    collection = db['logs']
    logger.info("✅ MongoDB connected!")
except Exception as e:
    logger.error(f"❌ MongoDB connection error: {e}")
    sys.exit(1)

# AES Encryption Setup
AES_KEY = os.urandom(32)  # 256-bit AES key
IV = os.urandom(16)  # 128-bit IV

print("IV: ",IV)

# RSA Encryption Setup
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

# Helper Functions
def encrypt_aes(data, aes_key, iv):
    """ Encrypt data using AES in CFB mode. """
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data.encode()) + encryptor.finalize()
    return base64.b64encode(encrypted_data).decode('utf-8')




def decrypt_aes(enc_data, aes_key, iv_base64):
    """ Decrypt data using AES in CFB mode. """
    try:
        iv = base64.b64decode(iv_base64)  # Decode IV from Base64
        enc_data_bytes = base64.b64decode(enc_data)  # Decode encrypted data
        
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(enc_data_bytes) + decryptor.finalize()
        
        return decrypted_data.decode('utf-8')
    except Exception as e:
        logger.error(f"Error decrypting data: {e}")
        return None


def encrypt_rsa(public_key, aes_key):
    """ Encrypt the AES key using RSA. """
    rsa_encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(rsa_encrypted_aes_key).decode('utf-8')

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import base64


def decrypt_rsa(encrypted_aes_key_b64, private_key):
    """Decrypt the RSA-encrypted AES key."""
    try:
        # Log the encrypted AES key for debugging
        logger.info(f"Encrypted AES Key (Base64): {encrypted_aes_key_b64}")

        # Decode the Base64-encoded encrypted AES key
        encrypted_aes_key_bytes = base64.b64decode(encrypted_aes_key_b64)
        
        # Ensure private_key is valid and supports decryption
        if not hasattr(private_key, "decrypt"):
            raise ValueError("Invalid private key provided for decryption.")

        print("encrypted_aes_key_bytes:", encrypted_aes_key_bytes)

        # Decrypt the AES key using RSA
        decrypted_aes_key_bytes = private_key.decrypt(
            encrypted_aes_key_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Log the decrypted AES key (Base64 encoded for safety)
        decrypted_aes_key_b64 = base64.b64encode(decrypted_aes_key_bytes).decode('utf-8')
        print(f"Decrypted AES Key (Base64): {decrypted_aes_key_b64}")
        logger.info(f"Decrypted AES Key (Base64): {decrypted_aes_key_b64}")

        # Return the raw AES key (usually 16, 24, or 32 bytes)
        return decrypted_aes_key_bytes  

    except Exception as e:
        logger.error(f"Error decrypting AES key: {e}")
        return None


# Routes
@app.route('/')
def home():
    return jsonify({"message": "Network Intrusion Detection System API is running!"})

from scapy.all import sniff, IP, TCP
import numpy as np
from flask import jsonify
import logging



@app.route('/capture', methods=['GET'])
def capture():
    """ Capture packet, classify intrusion, encrypt features, and store in database. """
    if model is None:
        logger.error("❌ Model not loaded")
        return jsonify({"error": "Model not loaded"}), 500

    def extract_features(packet):
        """ Extract features from a packet. """
        if IP in packet and TCP in packet:
            ip = packet[IP]
            tcp = packet[TCP]
            features = {
                "Fwd Packet Length Mean": len(ip),
                "Subflow Fwd Bytes": len(ip),
                "Fwd Packet Length Max": len(ip),
                "Total Length of Fwd Packets": len(ip),
                "Flow IAT Max": 0.5,  # Placeholder, replace with actual calculation
                "Flow Duration": 1.0,  # Placeholder, replace with actual calculation
                "Total Length of Bwd Packets": len(ip),
                "Subflow Bwd Bytes": len(ip),
                "Bwd Packets/s": 700,  # Placeholder, replace with actual calculation
                "Average Packet Size": len(ip),
                "Avg Bwd Segment Size": len(ip),
                "Flow Packets/s": 1000,  # Placeholder, replace with actual calculation
                "Destination Port": tcp.dport,
                "Avg Fwd Segment Size": len(ip),
                "Init_Win_bytes_backward": 1200,  # Placeholder, replace with actual calculation
                "Bwd Packet Length Max": len(ip),
                "Fwd Packet Length Std": 1400,  # Placeholder, replace with actual calculation
                "Packet Length Mean": len(ip),
                "Bwd Packet Length Std": 1600,  # Placeholder, replace with actual calculation
                "Fwd Header Length": len(ip)
            }
            return features
        return None

    # Variable to store the response
    capture_response = [None]  # Using a list to allow modification in nested function

    def packet_callback(packet):
        """ Callback function for packet sniffing. """
        features = extract_features(packet)
        if features:
            try:
                # Convert features to numpy array for model prediction
                feature_values = np.array(list(features.values())).reshape(1, -1)
                prediction = model.predict(feature_values)[0]

                # Mapping dictionary for predictions
                prediction_labels = {
                    0: "✅ BENIGN",
                    1: "🤖 Bot",
                    2: "💻 DDoS",
                    3: "🚀 DoS GoldenEye",
                    4: "🔥 DoS Hulk",
                    5: "⚡ DoS Slowhttptest",
                    6: "🌪️ DoS slowloris",
                    7: "🔐 FTP-Patator",
                    8: "❤️ Heartbleed",
                    9: "👁️ Infiltration",
                    10: "🔍 PortScan",
                    11: "🔑 SSH-Patator"
                }

                prediction_label = prediction_labels.get(int(prediction), "Unknown")

                # Encrypt each feature individually using AES
                encrypted_features = {}
                for feature, value in features.items():
                    encrypted_features[feature] = encrypt_aes(str(value), AES_KEY, IV)

                # Encrypt the prediction label using AES
                encrypted_prediction = encrypt_aes(prediction_label, AES_KEY, IV)

                # Encrypt the AES key using RSA
                encrypted_aes_key = encrypt_rsa(public_key, AES_KEY)

                # Prepare the log entry for MongoDB
                log_entry = {
                    "original_features": features,
                    "encrypted_features": encrypted_features,
                    "encrypted_prediction": encrypted_prediction,
                    "rsa_encrypted_aes_key": encrypted_aes_key,
                    "IV": base64.b64encode(IV).decode('utf-8')
                }

                # Insert into MongoDB
                result = collection.insert_one(log_entry)
                if result.acknowledged:
                    logger.info(f"✅ Log inserted into MongoDB: {log_entry}")
                else:
                    logger.warning("⚠️ MongoDB insertion not acknowledged")

                # Prepare the response
                response = {
                    "status": "Intrusion" if prediction != 0 else "No Intrusion",
                    "type": prediction_label,
                    "original_features": features,
                    "encrypted_features": encrypted_features,
                    "encrypted_prediction": encrypted_prediction,
                    "AES_KEY": base64.b64encode(AES_KEY).decode('utf-8'),
                    "encrypted_aes_key": encrypted_aes_key,
                    "IV": base64.b64encode(IV).decode('utf-8')
                }
                logger.info(f"📡 Response: {response}")
                
                # Store the response
                capture_response[0] = response

            except Exception as e:
                logger.error(f"❌ Model prediction or encryption failed: {e}")
                capture_response[0] = {"error": f"Model prediction or encryption failed: {str(e)}"}

    # Start sniffing packets (blocking operation)
    sniff(prn=packet_callback, count=1)  # Capture 1 packet

    # Return the stored response
    if capture_response[0] is None:
        return jsonify({"status": "No packet captured"}), 200
    elif "error" in capture_response[0]:
        return jsonify(capture_response[0]), 500
    return jsonify(capture_response[0]), 200


@app.route('/user1/classify', methods=['POST'])
def user1_classify():
    """ 
    User 1: Classify features, encrypt each feature individually, encrypt the result, and store in database.
    Returns encrypted features, encrypted result, and encrypted AES key.
    """
    try:
        data = request.json
        required_features = [
            "Fwd Packet Length Mean", "Subflow Fwd Bytes", "Fwd Packet Length Max", "Total Length of Fwd Packets",
            "Flow IAT Max", "Flow Duration", "Total Length of Bwd Packets", "Subflow Bwd Bytes", "Bwd Packets/s",
            "Average Packet Size", "Avg Bwd Segment Size", "Flow Packets/s", "Destination Port", "Avg Fwd Segment Size",
            "Init_Win_bytes_backward", "Bwd Packet Length Max", "Fwd Packet Length Std", "Packet Length Mean",
            "Bwd Packet Length Std", "Fwd Header Length"
        ]

        # Validate input
        for feature in required_features:
            if feature not in data:
                return jsonify({"error": f"Missing feature: {feature}"}), 400

        # Encrypt each feature individually using AES
        encrypted_features = {}
        for feature in required_features:
            feature_value = str(data[feature])  # Convert feature value to string
            encrypted_features[feature] = encrypt_aes(feature_value, AES_KEY, IV)  # Encrypt the feature value

        # Convert input data to numpy array for model prediction
        feature_values = np.array([float(data[feature]) for feature in required_features]).reshape(1, -1)

        # Predict using the model
        prediction = model.predict(feature_values)[0]

        # Mapping dictionary for predictions
        prediction_labels = {
            0: "✅ BENIGN",
            1: "🤖 Bot",
            2: "💻 DDoS",
            3: "🚀 DoS GoldenEye",
            4: "🔥 DoS Hulk",
            5: "⚡ DoS Slowhttptest",
            6: "🌪️ DoS slowloris",
            7: "🔐 FTP-Patator",
            8: "❤️ Heartbleed",
            9: "👁️ Infiltration",
            10: "🔍 PortScan",
            11: "🔑 SSH-Patator"
        }

        # Map prediction to label
        prediction_label = prediction_labels.get(int(prediction), "Unknown")

        # Encrypt the prediction label using AES
        encrypted_prediction = encrypt_aes(prediction_label, AES_KEY, IV)

        # Encrypt the AES key using RSA
        encrypted_aes_key = encrypt_rsa(public_key, AES_KEY)

        # Store encrypted features and encrypted prediction in MongoDB
        collection.insert_one({
            "encrypted_features": encrypted_features,
            "encrypted_prediction": encrypted_prediction,
            "rsa_encrypted_aes_key": encrypted_aes_key,
            "IV": base64.b64encode(IV).decode('utf-8')
        })

        # Return encrypted features, encrypted prediction, and encrypted AES key
        return jsonify({
            "prediction_label": prediction_label,
            "encrypted_features": encrypted_features,
            "encrypted_prediction": encrypted_prediction,
            "AES_KEY": base64.b64encode(AES_KEY).decode('utf-8'),  # Encode AES_KEY to Base64
            "encrypted_aes_key": encrypted_aes_key,
            "IV": base64.b64encode(IV).decode('utf-8')  # Encode IV to Base64
        })
    except Exception as e:
        logger.error(f"Error in user1_classify: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/user2/logs', methods=['GET'])
def user2_logs():
    """ 
    User 2: Fetch encrypted logs (features and predictions) and the encrypted AES key from the database.
    """
    try:
        logs = []
        for log in collection.find():
            logger.info(f"Log found: {log}")  # Log the entire log document

            encrypted_features = log.get("encrypted_features", {})
            encrypted_prediction = log.get("encrypted_prediction", "")
            encrypted_aes_key = log.get("rsa_encrypted_aes_key", "")  # Fetch the encrypted AES key from the log
            iv = log.get("IV", "")
            if not encrypted_features:
                logger.warning(f"Missing or empty 'encrypted_features' in log with id: {log.get('_id', 'Unknown')}")
            
            logs.append({
                "id": str(log.get("_id", "")),
                "encrypted_features": encrypted_features,
                "encrypted_prediction": encrypted_prediction,
                "encrypted_aes_key": encrypted_aes_key,  # Include the encrypted AES key within each log entry
                "iv": iv
            })
        
        logger.info(f"Encrypted logs: {logs}")  # Log the final list of logs
        
        # Return encrypted logs with the encrypted AES key included in each log entry
        return jsonify({
            "encrypted_logs": logs
        })
    except Exception as e:
        logger.error(f"Error fetching logs: {e}")
        return jsonify({"error": "Failed to fetch logs"}), 500

@app.route('/user2/decrypt', methods=['POST'])
def user2_decrypt():
    """ 
    User 2: Decrypt AES key, encrypted features, and encrypted predictions.
    """
    try:
        data = request.get_json()

        logger.info(f"Received request: {data}")

        # Validate request data
        if not data or "encrypted_logs" not in data:
            logger.error("Invalid request: Missing required fields")
            return jsonify({"error": "Invalid request: Missing required fields"}), 400

        encrypted_logs = data["encrypted_logs"]

        if not isinstance(encrypted_logs, list) or not encrypted_logs:
            logger.error("Invalid request: 'encrypted_logs' should be a non-empty list")
            return jsonify({"error": "Invalid request: 'encrypted_logs' should be a non-empty list"}), 400

        # Fetch the RSA encrypted AES key from the first log entry
        encrypted_aes_key = encrypted_logs[0].get("encrypted_aes_key", "")
        if not encrypted_aes_key:
            logger.error("Missing RSA encrypted AES key in logs")
            return jsonify({"error": "Missing RSA encrypted AES key in logs"}), 400
        print("encrypted_aes_key",encrypted_aes_key)
        # Decrypt AES key using RSA
        decrypted_aes_key = decrypt_rsa(encrypted_aes_key, private_key)
        if not decrypted_aes_key:
            logger.error("Failed to decrypt AES key")
            return jsonify({"error": "Failed to decrypt AES key"}), 400

        # Initialize decrypted logs list
        decrypted_logs = []

        # Decrypt each log entry
        for log in encrypted_logs:
            decrypted_features = {}
            encrypted_features = log.get("encrypted_features", {})
            iv = log.get("iv", "")  # Fetch IV from the log entry

            if not iv:
                logger.error("Missing IV in log entry")
                return jsonify({"error": "Missing IV in log entry"}), 400

            if not isinstance(encrypted_features, dict):
                logger.error("Invalid format for 'encrypted_features'")
                return jsonify({"error": "Invalid format for 'encrypted_features'"}), 400

            # Decrypt each feature
            for feature, encrypted_value in encrypted_features.items():
                try:
                    decrypted_feature = decrypt_aes(encrypted_value, decrypted_aes_key, iv)
                    decrypted_features[feature] = decrypted_feature if decrypted_feature else "Decryption Failed"
                except Exception as e:
                    logger.error(f"Failed to decrypt feature '{feature}': {e}")
                    decrypted_features[feature] = "Decryption Failed"

            # Decrypt prediction
            encrypted_prediction = log.get("encrypted_prediction", "")
            decrypted_prediction = "Decryption Failed"
            if encrypted_prediction:
                try:
                    decrypted_prediction = decrypt_aes(encrypted_prediction, decrypted_aes_key, iv)
                except Exception as e:
                    logger.error(f"Failed to decrypt prediction: {e}")

            # Append decrypted log to the result
            decrypted_logs.append({
                "id": log.get("id", "Unknown"),
                "decrypted_features": decrypted_features,
                "decrypted_prediction": decrypted_prediction
            })

        logger.info(f"Decryption successful: {decrypted_logs}")
        return jsonify({"decrypted_logs": decrypted_logs})

    except Exception as e:
        logger.error(f"Unexpected error in user2_decrypt: {e}")
        return jsonify({"error": "Internal Server Error"}), 500


# Run the Flask app
if __name__ == '__main__':
    try:
        app.run(debug=True)
    except Exception as e:
        logger.error(f"❌ Error running Flask server: {e}")
