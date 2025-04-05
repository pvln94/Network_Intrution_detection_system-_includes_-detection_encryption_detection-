# Network Intrusion Detection System (NIDS) - Detection & Encryption

## Overview  
This project is a Network Intrusion Detection System (NIDS) that uses a Random Forest Classifier to detect malicious network activity based on the CICIDS 2017 Dataset. To ensure data security, the system encrypts feature values and predictions using AES encryption, and RSA encryption is used for secure data transmission between users.

## Features

### Intrusion Detection Model:
- *Model*: Random Forest Classifier (We performed many models on dataset, but among all RF gave best results. Some more best performed models are available in backend models folders in joblib format. For results of RF, you can vist coding folder ->  CICIDS_Training.ipynb file.)
- *Dataset*: CICIDS 2017 Dataset
- *Performance Metrics*:
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
- *Feature Encryption (AES)*: To prevent data leaks, extracted feature values and prediction results are encrypted using AES before storage.
- *Secure Transmission (RSA)*: For secure communication, RSA encryption is used between users to prevent intruder access.
- *Database Security (MongoDB)*: Encrypted data is stored in MongoDB, ensuring access only to authenticated users.

## Communication Flow:

### User 1 (Sender):
1. Can capture real-time network packet data using ScaPy or manually enter network features.
2. Encrypts feature values and intrusion detection results using AES.
3. Stores the encrypted data in MongoDB.

### User 2 (Client):
1. Can access the encrypted intrusion logs from MongoDB by clicking on Fetch Logs.
2. Uses RSA private key (shared securely by User 1) to decrypt and analyze the logs.

## User Interface (UI)
- *Multi-user Login System*: Allows multiple users to log in with authentication.
  
### User 1 (Sender):
- Options to capture packet information in real-time or enter data manually.
- Stores encrypted data in the database.

### User 2 (Client):
- Can fetch logs from the database and decrypt them using a private key.

## Security Considerations
- If an intruder gains access to unencrypted data, they could analyze network behaviors and bypass detection mechanisms.
- AES and RSA encryption ensure only authenticated users can access and decrypt logs.
- Secure private key sharing must be done via a safe channel (e.g., manually or via a secure key exchange protocol).


## Frontend:
## For fronend part you can refer to *nids-frontend*
### Framework & Stack:

*⚛ React with JavaScript (not TypeScript variant)*

*🚀 Vite as the build tool (faster alternative to Create React App)*

*📦 Node.js/npm for package management*

### cmd: npm run dev

![image](https://github.com/user-attachments/assets/fb4b4310-353d-4fe5-a835-1c6cc9f62bf4)

![image](https://github.com/user-attachments/assets/af5a417e-1093-439c-94d2-9a75077de6fd)



## Backend:
## For backend you can refer to *backend*
*Framework: Flask (Python)*

*Database: MongoDB (with PyMongo)*

*Security: AES + RSA encryption handlers*

### cmd: python app.py

![image](https://github.com/user-attachments/assets/f9ae83c2-99ff-433b-ba79-2b82536acfe6)


![image](https://github.com/user-attachments/assets/3fe1e82c-fc00-4783-99f4-684181756f8d)


## Database:
### MongoDB
![image](https://github.com/user-attachments/assets/29364cf9-0d85-4991-ab2e-69ae731d2666)



## Functionality:
### login: Credentials for user-1,2
### User1: *user1, pass1*
### User2: *user2, pass2*
![image](https://github.com/user-attachments/assets/32a6ac88-ba27-4e3e-a64c-e8d3cf7db11e)

## User1:
![image](https://github.com/user-attachments/assets/f39f04f5-1793-409b-9009-71979dc77649)

### on clicking *Capture Packet*, using scapy, the required packet features are obtained
### Uses of Scapy in Networking
🔹 Packet sniffing – Capture live network packets
🔹 Packet crafting – Create custom network packets
🔹 Network scanning – Scan open ports, IPs, and MAC addresses
🔹 Protocol testing – Test custom network protocols
🔹 Network attacks & penetration testing – Perform ARP spoofing, DoS attacks, etc.
🔹 Firewall testing – Check if firewalls are blocking certain packets

![image](https://github.com/user-attachments/assets/aecd4de4-5a49-457f-bdc4-4f2809c20a0e)

### Add Manually
![image](https://github.com/user-attachments/assets/12884298-08ea-461d-860e-8271b892d8cd)


## User2:
### login:
![image](https://github.com/user-attachments/assets/a66a52fa-14c3-4116-baa9-6c18640c0340)

### Fetch logs:
![image](https://github.com/user-attachments/assets/0b110e4b-d829-4e21-9bfa-4c3a31e8de47)

### Decrypt logs:
![image](https://github.com/user-attachments/assets/9e90d57b-a312-4e0f-9427-845b6b064b44)
