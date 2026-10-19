from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import socket
import threading
import base64

# Manejar conexion y envio de llaves
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096,
    backend=default_backend()
)
public_key = private_key.public_key()

public_partner = None

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("localhost", 9999))
server.listen()

print("Esperando conexion...")

# Conexion con cliente
client, _ = server.accept()

# Se prepara PEM de llave publica
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Se envia llave publica a cliente
client.send(public_pem)

# Carga llave publica de cliente
public_partner = serialization.load_pem_public_key(
        client.recv(1024),
        backend=default_backend()
    )

def main():
    print("Bienvenido a Securechat 1.0")
    print("Escribe tu mensaje o 'salir' para terminar")
    print("Bob se ha conectado")

    send_thread = threading.Thread(target=sending_messages, args=(client,))
    recv_thread = threading.Thread(target=receiving_messages, args=(client,))
    send_thread.start()
    recv_thread.start()
    send_thread.join()
    recv_thread.join()

# Maneja comportamiento para recibir mensajes
def receiving_messages(c):
    while True:
        msg = c.recv(1024)
        decrypted = private_key.decrypt(base64.b64decode(msg),
                                        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                     algorithm=hashes.SHA256(),
                                                     label=None
                                                     )
                                        )
        decrypted_str = decrypted.decode()
        if decrypted_str == "salir":
            print("Bob se ha desconectado")
            c.send("salir".encode())
            break
        print()
        print("Bob: " + decrypted_str)

# Maneja envio de mensajes
def sending_messages(c):
    while True:
        print()
        message = input("Yo: ")
        encrypted = base64.b64encode(public_partner.encrypt(message.encode(),
                                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                  algorithm=hashes.SHA256(),
                                                                  label=None)
                                                                 )
                                     )
        if message.lower() == "salir":
            c.send(encrypted)
            break

        c.send(encrypted)

if __name__ == "__main__":
    main()
