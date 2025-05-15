import socket
import threading
import os
import sys
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes, serialization
from colorama import init, Fore, Style

init(autoreset=True)
clients = {}
session_keys = {}
usernames = {}

def derive_session_key(shared_key: bytes):
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'LANChat')
    return hkdf.derive(shared_key)

def encrypt(data: bytes, key):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    return nonce + aesgcm.encrypt(nonce, data, None)

def decrypt(data: bytes, key):
    aesgcm = AESGCM(key)
    nonce = data[:12]
    ciphertext = data[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)

def key_exchange(conn):
    parameters_pem = b""
    while not parameters_pem.endswith(b"-----END DH PARAMETERS-----\n"):
        parameters_pem += conn.recv(1024)
    parameters = serialization.load_pem_parameters(parameters_pem)

    client_pub_key_pem = b""
    while not client_pub_key_pem.endswith(b"-----END PUBLIC KEY-----\n"):
        client_pub_key_pem += conn.recv(1024)
    client_pub_key = serialization.load_pem_public_key(client_pub_key_pem)

    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    conn.send(public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))
    shared_key = private_key.exchange(client_pub_key)
    return derive_session_key(shared_key)

def broadcast(message, exclude=None):
    for client, key in session_keys.items():
        if client != exclude:
            try:
                client.send(encrypt(message.encode(), key))
            except Exception as e:
                print(f"[Broadcast error]: {e}")

def handle_client(conn):
    session_key = key_exchange(conn)
    session_keys[conn] = session_key

    conn.send(encrypt(b"Enter your username: ", session_key))
    username = decrypt(conn.recv(1024), session_key).decode()
    usernames[conn] = username

    join_msg = f"[{username} joined]"
    print(join_msg)
    broadcast(join_msg)

    while True:
        try:
            data = conn.recv(4096)
            if not data:
                break
            message = decrypt(data, session_key).decode()
            full_msg = f"{username}: {message}"
            print(full_msg)
            broadcast(full_msg, exclude=conn)
        except:
            break

    leave_msg = f"[{username} left]"
    print(leave_msg)
    broadcast(leave_msg)
    del usernames[conn]
    del session_keys[conn]
    conn.close()

def server_input_loop():
    server_color = Fore.RED + "server: " + Style.RESET_ALL
    while True:
        message = input(server_color)
        if message.strip():
            full_msg = f"server: {message}"
            broadcast(full_msg)  # Don't print again, input() already did

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('', 12345))
    server.listen()
    print("Server listening on port 12345")

    threading.Thread(target=server_input_loop, daemon=True).start()

    while True:
        conn, _ = server.accept()
        threading.Thread(target=handle_client, args=(conn,), daemon=True).start()

if __name__ == "__main__":
    main()
