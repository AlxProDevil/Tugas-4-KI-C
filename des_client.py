import socket
import pickle
import os
from des import des_encrypt_ecb, des_decrypt_ecb
import rsa

HOST = input("Enter the server's IP address: ").strip()
PORT = 65432

def send_data(conn, payload):
    payload_bytes = pickle.dumps(payload)
    payload_len = len(payload_bytes).to_bytes(4, 'big')
    conn.sendall(payload_len + payload_bytes)

def recv_data(conn):
    payload_len_bytes = conn.recv(4)
    if not payload_len_bytes:
        return None
    payload_len = int.from_bytes(payload_len_bytes, 'big')
    payload_bytes = conn.recv(payload_len)
    return pickle.loads(payload_bytes)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    try:
        s.connect((HOST, PORT))
        print(f"Connected to server {HOST}:{PORT}")

        print("\n[RSA] Negotiating secret key...")

        public_key = recv_data(s)
        if not public_key:
            raise Exception("Server disconnected during key exchange")
        print("[RSA] Server's public key diterima.")

        key = os.urandom(8)
        print(f"[RSA] Generated 8-byte DES key (hex): {key.hex()}")

        encrypted_des_key = rsa.encrypt(public_key, key)
        print("[RSA] DES key dienkripsi.")

        send_data(s, encrypted_des_key)
        print("[RSA] Encrypted DES key dikirim ke server.")

        print(f"\n[RSA] Secret DES key established!")
        print("========================================")


        print("You talk first. Type 'exit' to quit.")
        while True:
            message = input("[You]: ")
            plaintext = message.encode('utf-8')
            ciphertext = des_encrypt_ecb(plaintext, key)
            
            print(f"[Sending Ciphertext (hex)]: {ciphertext.hex()}")
            s.sendall(ciphertext)

            if message.lower() == 'exit':
                break

            print("[Waiting for server's reply...]")
            data = s.recv(1024)
            if not data:
                print("\n[Server disconnected]")
                break
            
            print(f"[Received Ciphertext (hex)]: {data.hex()}")
            decrypted = des_decrypt_ecb(data, key).decode('utf-8', errors='ignore')
            print(f"[Server]: {decrypted}")

            if decrypted.lower() == 'exit':
                break

    except ConnectionRefusedError:
        print(f"Could not connect to server at {HOST}:{PORT}.")
    except Exception as e:
        print(f"An error occurred: {e}")

    print("Connection closed.")