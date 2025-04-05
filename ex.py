# # # # this is just to check whether mongodb is working or not
# # # # It is working
# # # from pymongo import MongoClient

# # # # Connect to MongoDB (assuming it's running on localhost and default port 27017)
# # # client = MongoClient("mongodb://localhost:27017/")

# # # # Create or access the database
# # # db = client["my_database"]

# # # # Create or access a collection (similar to a table in SQL)
# # # collection = db["my_collection"]

# # # # Example data to insert (can be a dictionary or list of dictionaries)
# # # data = {
# # #     "name": "John Doe",
# # #     "age": 28,
# # #     "profession": "Software Engineer"
# # # }

# # # # Insert the data into the collection
# # # inserted_id = collection.insert_one(data).inserted_id

# # # # Print the inserted data's ID
# # # print(f"Data inserted with ID: {inserted_id}")


# # import os
# # import base64
# # from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# # from cryptography.hazmat.primitives import serialization, hashes
# # from cryptography.hazmat.primitives.asymmetric import rsa, padding
# # from cryptography.hazmat.backends import default_backend

# # # AES Encryption Setup
# # AES_KEY = os.urandom(32)  # 256-bit AES key
# # IV = os.urandom(16)  # 128-bit IV

# # def encrypt_aes(data):
# #     """
# #     Encrypt data using AES in CFB mode.
# #     """
# #     cipher = Cipher(algorithms.AES(AES_KEY), modes.CFB(IV), backend=default_backend())
# #     encryptor = cipher.encryptor()
# #     encrypted_data = encryptor.update(data.encode()) + encryptor.finalize()
# #     return base64.b64encode(encrypted_data).decode('utf-8')

# # def decrypt_aes(enc_data):
# #     """
# #     Decrypt data using AES in CFB mode.
# #     """
# #     try:
# #         cipher = Cipher(algorithms.AES(AES_KEY), modes.CFB(IV), backend=default_backend())
# #         decryptor = cipher.decryptor()
# #         decrypted_data = decryptor.update(base64.b64decode(enc_data)) + decryptor.finalize()
# #         return decrypted_data.decode()
# #     except Exception as e:
# #         return f"Error decrypting data: {e}"

# # # RSA Encryption Setup
# # # Generate RSA keys
# # private_key = rsa.generate_private_key(
# #     public_exponent=65537,
# #     key_size=2048,
# #     backend=default_backend()
# # )
# # public_key = private_key.public_key()

# # def encrypt_rsa(public_key, aes_key):
# #     """
# #     Encrypt the AES key using RSA.
# #     """
# #     rsa_encrypted_aes_key = public_key.encrypt(
# #         aes_key,
# #         padding.OAEP(
# #             mgf=padding.MGF1(algorithm=hashes.SHA256()),
# #             algorithm=hashes.SHA256(),
# #             label=None
# #         )
# #     )
# #     return base64.b64encode(rsa_encrypted_aes_key).decode('utf-8')  # Encode as Base64

# # def decrypt_rsa(encrypted_aes_key_b64):
# #     """
# #     Decrypt the RSA-encrypted AES key.
# #     """
# #     try:
# #         # Ensure proper Base64 padding
# #         padding_length = len(encrypted_aes_key_b64) % 4
# #         if padding_length:
# #             encrypted_aes_key_b64 += '=' * (4 - padding_length)

# #         # Decode the Base64 string
# #         encrypted_aes_key_bytes = base64.b64decode(encrypted_aes_key_b64)

# #         # Decrypt RSA-encrypted AES key
# #         decrypted_aes_key = private_key.decrypt(
# #             encrypted_aes_key_bytes,
# #             padding.OAEP(
# #                 mgf=padding.MGF1(algorithm=hashes.SHA256()),
# #                 algorithm=hashes.SHA256(),
# #                 label=None
# #             )
# #         )
# #         return decrypted_aes_key
# #     except Exception as e:
# #         return f"Error decrypting AES key: {e}"

# # # Example Usage
# # if __name__ == "__main__":
# #     # Example features (input to the model)
# #     features = "Fwd Packet Length Mean=14, Flow Duration=0.5, Destination Port=80"

# #     # Encrypt features using AES
# #     encrypted_features = encrypt_aes(features)
# #     print("Encrypted Features:", encrypted_features)

# #     # Decrypt features using AES
# #     decrypted_features = decrypt_aes(encrypted_features)
# #     print("Decrypted Features:", decrypted_features)

# #     print("original features:",features)

# #     # Encrypt AES key using RSA
# #     encrypted_aes_key = encrypt_rsa(public_key, AES_KEY)
# #     print("Encrypted AES Key (RSA):", encrypted_aes_key)

# #     # Decrypt AES key using RSA
# #     decrypted_aes_key = decrypt_rsa(encrypted_aes_key)
# #     print("Decrypted AES Key (RSA):", decrypted_aes_key)

# #     print("AES Key: ",AES_KEY)

# from cryptography.hazmat.primitives import serialization, hashes
# from cryptography.hazmat.primitives.asymmetric import padding, rsa
# from cryptography.hazmat.backends import default_backend
# import base64
# import os

# # Generate RSA key pair
# private_key = rsa.generate_private_key(
#     public_exponent=65537,
#     key_size=2048,
#     backend=default_backend()
# )
# public_key = private_key.public_key()

# # Example AES key
# aes_key = os.urandom(32)  # 256-bit AES key

# def encrypt_rsa(public_key, aes_key):
#     """ Encrypt the AES key using RSA. """
#     rsa_encrypted_aes_key = public_key.encrypt(
#         aes_key,
#         padding.OAEP(
#             mgf=padding.MGF1(algorithm=hashes.SHA256()),
#             algorithm=hashes.SHA256(),
#             label=None
#         )
#     )
#     return base64.b64encode(rsa_encrypted_aes_key).decode('utf-8')

# def decrypt_rsa(encrypted_aes_key_b64, private_key):
#     """ Decrypt the RSA-encrypted AES key. """
#     try:
#         # Print the encrypted AES key for debugging
#         print(f"Encrypted AES Key (Base64): {encrypted_aes_key_b64}")

#         # Decode the Base64-encoded encrypted AES key
#         encrypted_aes_key_bytes = base64.b64decode(encrypted_aes_key_b64)
#         print(f"Encrypted AES Key (Bytes): {encrypted_aes_key_bytes}")

#         # Decrypt the AES key using RSA
#         decrypted_aes_key = private_key.decrypt(
#             encrypted_aes_key_bytes,
#             padding.OAEP(
#                 mgf=padding.MGF1(algorithm=hashes.SHA256()),
#                 algorithm=hashes.SHA256(),
#                 label=None
#             )
#         )
#         print(f"Decrypted AES Key (Bytes): {decrypted_aes_key}")
#         print(f"Decrypted AES Key (Base64): {base64.b64encode(decrypted_aes_key).decode('utf-8')}")

#         return decrypted_aes_key
#     except Exception as e:
#         print(f"Error decrypting AES key: {e}")
#         return None

# # Encrypt the AES key
# encrypted_aes_key_b64 = encrypt_rsa(public_key, aes_key)
# print(f"Encrypted AES Key (Base64): {encrypted_aes_key_b64}")

# # Print the original AES key
# print(f"Original AES Key (Bytes): {aes_key}")
# print(f"Original AES Key (Base64): {base64.b64encode(aes_key).decode('utf-8')}")

# # Decrypt the AES key
# decrypted_aes_key = decrypt_rsa(encrypted_aes_key_b64, private_key)
# if decrypted_aes_key:
#     print("Decryption successful!")
#     print(f"Decrypted AES Key (Bytes): {decrypted_aes_key}")
#     print(f"Decrypted AES Key (Base64): {base64.b64encode(decrypted_aes_key).decode('utf-8')}")
# else:
#     print("Decryption failed.")


import base64

# Encoded IV (example)
encoded_iv = "i+ppUCrrkEcqA6Z2O7fFfw=="

# Decode it
decoded_iv = base64.b64decode(encoded_iv)

print(decoded_iv)  # This will print the original IV as bytes
