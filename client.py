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
SESSION_KEY = None

def derive_session_key(shared_key: bytes):
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'LANChat')
    return hkdf.derive(shared_key)

def encrypt(data: bytes):
    aesgcm = AESGCM(SESSION_KEY)
    nonce = os.urandom(12)
    return nonce + aesgcm.encrypt(nonce, data, None)

def decrypt(data: bytes):
    aesgcm = AESGCM(SESSION_KEY)
    nonce = data[:12]
    ciphertext = data[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)

def key_exchange(sock):
    global SESSION_KEY
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    sock.send(parameters.parameter_bytes(encoding=serialization.Encoding.PEM, format=serialization.ParameterFormat.PKCS3))
    sock.send(public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))

    server_pub_key_pem = b""
    while not server_pub_key_pem.endswith(b"-----END PUBLIC KEY-----\n"):
        server_pub_key_pem += sock.recv(1024)

    server_pub_key = serialization.load_pem_public_key(server_pub_key_pem)
    shared_key = private_key.exchange(server_pub_key)
    SESSION_KEY = derive_session_key(shared_key)

def receive_messages(sock, prompt):
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                break
            try:
                message = decrypt(data).decode()
                sys.stdout.write(f"\r{message}\n{prompt}")
                sys.stdout.flush()
            except Exception as e:
                print(f"\r[Decrypt Error] {e}")
        except:
            break

def main():
    server_ip = input("Server IP: ")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((server_ip, 12345))

    print("Key exchange...")
    key_exchange(sock)
    print("Secure session established.")

    username = input("Your username: ")
    sock.send(encrypt(username.encode()))

    user_colors = [Fore.CYAN, Fore.YELLOW, Fore.GREEN, Fore.MAGENTA]
    user_color = user_colors[hash(username) % len(user_colors)]
    prompt = user_color + f"{username}: " + Style.RESET_ALL

    threading.Thread(target=receive_messages, args=(sock, prompt), daemon=True).start()

    while True:
        message = input(prompt)
        if message.strip():
            sock.send(encrypt(message.encode()))
        if message == "/quit":
            break

if __name__ == "__main__":
    main()
