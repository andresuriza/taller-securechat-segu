from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import scrypt
from Cryptodome.Util.number import long_to_bytes
import socket
import threading
import base64
import sys

# Manejar conexion y envio de llaves
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096,
    backend=default_backend()
)
public_key = private_key.public_key()

server_pkey = None

# Conexion con server
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("localhost", 9999))

# Se prepara PEM de llave publica
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Se envia llave publica a cliente
client.send(public_pem)

# Carga llave publica de cliente
server_pkey = serialization.load_pem_public_key(
        client.recv(1024),
        backend=default_backend()
    )

def main():
    print("Bienvenido a Securechat 1.0")
    print("Escribe tu mensaje o 'salir' para terminar")
    print("Alice se ha conectado")

    # Handshake
    encrypted = server_pkey.encrypt(b'hello',
                                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                              algorithm=hashes.SHA256(),
                                                              label=None)
                                                             )
    try:
        client.send(encrypted)
    except Exception as e:
        print(f"Error {e}")

    # Clave de sesion
    enc_session_key = client.recv(1024)
    session_key = private_key.decrypt(enc_session_key,
                                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                 algorithm=hashes.SHA256(),
                                                 label=None
                                                 )
                                    )

    # Hilos para enviar mensajes
    send_thread = threading.Thread(target=sending_messages, args=(client, session_key))
    recv_thread = threading.Thread(target=receiving_messages, args=(client, session_key))
    send_thread.start()
    recv_thread.start()


# Maneja comportamiento para recibir mensajes
def receiving_messages(c, session_key):
    while True:
        enc_msg = c.recv(1024)

        # Nonce
        cipher = AES.new(session_key, AES.MODE_GCM, enc_msg[:16])

        try:
            # Se obtiene el ciphertext y el tag
            rsa_enc = cipher.decrypt_and_verify(enc_msg[16:-16], enc_msg[-16:])
        except ValueError:
            print("Fallo en desencriptacion")

        # Desencriptar con RSA
        msg = private_key.decrypt(rsa_enc,
                                        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                     algorithm=hashes.SHA256(),
                                                     label=None
                                                     )
                                        )

        # Convertir de bytes a string
        msg_str = msg.decode()

        # Manejo de terminacion
        if msg_str == "salir":
            print("Alice se ha desconectado")
            c.send("salir".encode())
            break

        print()
        print("Alice: " + msg_str)

# Maneja envio de mensajes
def sending_messages(c, session_key):
    while True:
        print()
        msg = input("Yo: ")

        rsa_enc = server_pkey.encrypt(msg.encode(),
                                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                  algorithm=hashes.SHA256(),
                                                                  label=None)
                                                                 )
        # Nonce
        cipher = AES.new(session_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(rsa_enc)

        # Mensaje encriptado con AES256-GCM
        msg_enc = cipher.nonce + ciphertext + tag

        # Manejo de terminacion chat
        if msg.lower() == "salir":
            c.send(msg_enc)
            break

        c.send(msg_enc)

if __name__ == "__main__":
    main()
