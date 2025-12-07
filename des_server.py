import socket
import pickle
from des import des_decrypt_ecb, des_encrypt_ecb
import rsa

HOST = '0.0.0.0'
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
    s.bind((HOST, PORT))
    s.listen()
    print(f"Server listening on {HOST}:{PORT}...")

    conn, addr = s.accept()
    with conn:
        print("Connected by", addr)
        
        try:
            print("\n[RSA] Membuat 512-bit RSA key pair untuk Server...")
            server_public_key, server_private_key = rsa.generate_key_pair(512)
            print("[RSA] Key pair Server dibuat.")

            send_data(conn, server_public_key)
            print("[RSA] Public key Server dikirim ke client.")

            client_public_key = recv_data(conn)
            if not client_public_key: raise Exception("Gagal menerima Public Key Client")
            print("[RSA] Public key Client diterima.")

            encrypted_des_key = recv_data(conn)
            if not encrypted_des_key:
                raise Exception("Client disconnected during key exchange")
            
            print("[RSA] Encrypted DES key diterima.")

            key = rsa.decrypt(server_private_key, encrypted_des_key)
            if len(key) != 8:
                key = key.rjust(8, b'\x00')
                
            print(f"\n[RSA] Secret DES key established!")
            print(f"[RSA] Derived 8-byte DES key (hex): {key.hex()}")
            print("========================================")

            print("Waiting for client to talk first...")
            
            while True:
                incoming_pkg = recv_data(conn)
                if not incoming_pkg:
                    print("\n[Client disconnected]")
                    break
                
                ciphertext, signature = incoming_pkg
                
                print(f"\n[Received Ciphertext (hex)]: {ciphertext.hex()}")
                
                print(f"[Info] Signature yang digunakan pengirim: {hex(signature)}")
                
                decrypted_msg = des_decrypt_ecb(ciphertext, key).decode('utf-8', errors='ignore')
                
                is_valid = rsa.verify(client_public_key, decrypted_msg.encode('utf-8'), signature)
                validity_str = "VALID" if is_valid else "INVALID"
                print(f"[Info] Status Signature: {validity_str}")

                print(f"[Client]: {decrypted_msg}")

                if decrypted_msg.lower() == 'exit':
                    break

                message = input("[You]: ")
                plaintext_bytes = message.encode('utf-8')
                
                ciphertext = des_encrypt_ecb(plaintext_bytes, key)

                signature = rsa.sign(server_private_key, plaintext_bytes)
                print(f"[Info] Signature berhasil dibentuk: {hex(signature)}")

                send_data(conn, (ciphertext, signature))
                print(f"[Sending Ciphertext (hex)]: {ciphertext.hex()}")
                
                if message.lower() == 'exit':
                    break
        
        except Exception as e:
            print(f"An error occurred: {e}")

    print("Connection closed.")