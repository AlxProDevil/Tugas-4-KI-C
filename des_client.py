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
    payload_bytes = b""
    while len(payload_bytes) < payload_len:
        packet = conn.recv(payload_len - len(payload_bytes))
        if not packet: break
        payload_bytes += packet
    return pickle.loads(payload_bytes)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    try:
        s.connect((HOST, PORT))
        print(f"Connected to server {HOST}:{PORT}")

        print("\n[RSA] Negotiating secret key...")

        server_public_key = recv_data(s)
        if not server_public_key:
            raise Exception("Server disconnected during key exchange")
        print("[RSA] Server's public key diterima.")

        print("[RSA] Membuat 512-bit RSA key pair untuk Client...")
        client_public_key, client_private_key = rsa.generate_key_pair(512)
        
        send_data(s, client_public_key)
        print("[RSA] Public key Client dikirim ke server.")

        key = os.urandom(8)
        print(f"[RSA] Generated 8-byte DES key (hex): {key.hex()}")

        encrypted_des_key = rsa.encrypt(server_public_key, key)
        print("[RSA] DES key dienkripsi dengan Public Key Server.")

        send_data(s, encrypted_des_key)
        print("[RSA] Encrypted DES key dikirim ke server.")

        print(f"\n[RSA] Secret DES key established!")
        print("========================================")

        print("You talk first. Type 'exit' to quit.")
        
        while True:
            message = input("[You]: ")
            plaintext_bytes = message.encode('utf-8')
            
            ciphertext = des_encrypt_ecb(plaintext_bytes, key)
            
            signature = rsa.sign(client_private_key, plaintext_bytes)
            print(f"[Info] Signature berhasil dibentuk: {hex(signature)}")

            send_data(s, (ciphertext, signature))
            print(f"[Sending Ciphertext (hex)]: {ciphertext.hex()}")

            if message.lower() == 'exit':
                break

            print("[Waiting for server's reply...]")
            
            incoming_pkg = recv_data(s)
            if not incoming_pkg:
                print("\n[Server disconnected]")
                break
            
            ciphertext, signature = incoming_pkg
            
            print(f"\n[Received Ciphertext (hex)]: {ciphertext.hex()}")
            
            print(f"[Info] Signature yang digunakan pengirim: {hex(signature)}")
            
            decrypted_msg = des_decrypt_ecb(ciphertext, key).decode('utf-8', errors='ignore')
            
            is_valid = rsa.verify(server_public_key, decrypted_msg.encode('utf-8'), signature)
            validity_str = "VALID" if is_valid else "INVALID"
            print(f"[Info] Status Signature: {validity_str}")

            print(f"[Server]: {decrypted_msg}")

            if decrypted_msg.lower() == 'exit':
                break

    except ConnectionRefusedError:
        print(f"Could not connect to server at {HOST}:{PORT}.")
    except Exception as e:
        print(f"An error occurred: {e}")

    print("Connection closed.")