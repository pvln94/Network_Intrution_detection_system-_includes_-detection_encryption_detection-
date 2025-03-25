# Network Intrusion Detection System (NIDS) - Detection & Encryption

## Overview  
This project is a Network Intrusion Detection System (NIDS) that uses a Random Forest Classifier to detect malicious network activity based on the CICIDS 2017 Dataset. To ensure data security, the system encrypts feature values and predictions using AES encryption, and RSA encryption is used for secure data transmission between users.

## Features

### Intrusion Detection Model:
- **Model**: Random Forest Classifier
- **Dataset**: CICIDS 2017 Dataset
- **Performance Metrics**:
  - Accuracy: ~99.6%
  - F1 Score: ~0.992
  - Recall Score: ~0.994
  - Precision Score: ~0.991

### Feature Set Used:
The following features are extracted from network packets to train the model:

1. Fwd Packet Length Mean
2. Subflow Fwd Bytes
3. Fwd Packet Length Max
4. Total Length of Fwd Packets
5. Flow IAT Max
6. Flow Duration
7. Total Length of Bwd Packets
8. Subflow Bwd Bytes
9. Bwd Packets/s
10. Average Packet Size
11. Avg Bwd Segment Size
12. Flow Packets/s
13. Destination Port
14. Avg Fwd Segment Size
15. Init Win_bytes_backward
16. Bwd Packet Length Max
17. Fwd Packet Length Std
18. Packet Length Mean
19. Bwd Packet Length Std
20. Fwd Header Length

### Security Measures Implemented:
- **Feature Encryption (AES)**: To prevent data leaks, extracted feature values and prediction results are encrypted using AES before storage.
- **Secure Transmission (RSA)**: For secure communication, RSA encryption is used between users to prevent intruder access.
- **Database Security (MongoDB)**: Encrypted data is stored in MongoDB, ensuring access only to authenticated users.

## Communication Flow:

### User 1 (Sender):
1. Can capture real-time network packet data using SciPy or manually enter network features.
2. Encrypts feature values and intrusion detection results using AES.
3. Stores the encrypted data in MongoDB.

### User 2 (Client):
1. Can access the encrypted intrusion logs from MongoDB by clicking on Fetch Logs.
2. Uses RSA private key (shared securely by User 1) to decrypt and analyze the logs.

## User Interface (UI)
- **Multi-user Login System**: Allows multiple users to log in with authentication.
  
### User 1 (Sender):
- Options to capture packet information in real-time or enter data manually.
- Stores encrypted data in the database.

### User 2 (Client):
- Can fetch logs from the database and decrypt them using a private key.

## Security Considerations
- If an intruder gains access to unencrypted data, they could analyze network behaviors and bypass detection mechanisms.
- AES and RSA encryption ensure only authenticated users can access and decrypt logs.
- Secure private key sharing must be done via a safe channel (e.g., manually or via a secure key exchange protocol).
