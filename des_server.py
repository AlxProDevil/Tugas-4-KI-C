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
    payload_bytes = conn.recv(payload_len)
    return pickle.loads(payload_bytes)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print(f"Server listening on {HOST}:{PORT}...")

    conn, addr = s.accept()
    with conn:
        print("Connected by", addr)
        
        try:
            print("\n[RSA] Membuat 512-bit RSA key pair...")
            public_key, private_key = rsa.generate_key_pair(512)
            print("[RSA] Key pair dibuat.")

            send_data(conn, public_key)
            print("[RSA] Public key dikirim ke client.")

            encrypted_des_key = recv_data(conn)
            if not encrypted_des_key:
                raise Exception("Client disconnected during key exchange")
            
            print("[RSA] Encrypted DES key diterima.")

            key = rsa.decrypt(private_key, encrypted_des_key)
            
            if len(key) != 8:
                print(f"[Warning] Decrypted key length is not 8 bytes: {len(key)}")
                key = key.rjust(8, b'\x00')
                
            print(f"\n[RSA] Secret DES key established!")
            print(f"[RSA] Derived 8-byte DES key (hex): {key.hex()}")
            print("========================================")


            print("Waiting for client to talk first...")
            while True:
                data = conn.recv(1024)
                if not data:
                    print("\n[Client disconnected]")
                    break
                
                print(f"[Received Ciphertext (hex)]: {data.hex()}")
                
                decrypted = des_decrypt_ecb(data, key).decode('utf-8', errors='ignore')
                print(f"[Client]: {decrypted}")

                if decrypted.lower() == 'exit':
                    break

                message = input("[You]: ")
                plaintext = message.encode('utf-8')
                ciphertext = des_encrypt_ecb(plaintext, key)

                print(f"[Sending Ciphertext (hex)]: {ciphertext.hex()}")
                conn.sendall(ciphertext)
                
                if message.lower() == 'exit':
                    break
        
        except Exception as e:
            print(f"An error occurred: {e}")

    print("Connection closed.")