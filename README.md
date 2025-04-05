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

![image](https://github.com/user-attachments/assets/e27d85a2-2f1a-4b8b-9d94-086e256c44e2)

![image](https://github.com/user-attachments/assets/6fd19657-b574-4d1c-9ff7-a4c7b98e38f6)





## Backend:
## For backend you can refer to *backend*
*Framework: Flask (Python)*

*Database: MongoDB (with PyMongo)*

*Security: AES + RSA encryption handlers*

### cmd: python app.py

![image](https://github.com/user-attachments/assets/93482590-2ac2-4ae4-90c2-299b4ad77c50)

![image](https://github.com/user-attachments/assets/8ad09b06-31e7-4f2c-ac5b-aade3a46d7b0)



## Database:
### MongoDB
![image](https://github.com/user-attachments/assets/6124c07a-b5e4-49c4-ad68-13f3abbcb4d6)



## Functionality:
### login: Credentials for user-1,2
### User1: *user1, pass1*
### User2: *user2, pass2*
![image](https://github.com/user-attachments/assets/e5534bb8-94b3-4690-869f-e72559a03174)


## User1:
![image](https://github.com/user-attachments/assets/145a3e70-888f-4d48-b8eb-e9fbd01f2b8a)


### on clicking *Capture Packet*, using scapy, the required packet features are obtained
### Uses of Scapy in Networking
🔹 Packet sniffing – Capture live network packets
🔹 Packet crafting – Create custom network packets
🔹 Network scanning – Scan open ports, IPs, and MAC addresses
🔹 Protocol testing – Test custom network protocols
🔹 Network attacks & penetration testing – Perform ARP spoofing, DoS attacks, etc.
🔹 Firewall testing – Check if firewalls are blocking certain packets

![image](https://github.com/user-attachments/assets/0d87e1e0-f91b-4326-a1c9-ac2a8bd1cb0d)

![image](https://github.com/user-attachments/assets/c3dfb791-eff2-48bc-855d-fea840a902e4)



### Add Manually
![image](https://github.com/user-attachments/assets/71190c92-c1dd-4f9d-a3c6-4d7c9a5168c9)


## User2:
### login:
![image](https://github.com/user-attachments/assets/4e9e0939-63d6-4c7b-8e51-b20ad15521fe)

### Fetch logs:
![image](https://github.com/user-attachments/assets/09e5a748-41dd-4d64-b7be-c5fb6855f408)

![image](https://github.com/user-attachments/assets/aa9815ce-f675-4c57-9a8d-5baa5aa06b9d)

### Decrypt logs:
![image](https://github.com/user-attachments/assets/0e28b1a6-fc9f-4a9c-9886-a5d5693fe17d)
