import rsa
import socket
import threading

# Manejar conexion y envio de llaves
public_key, private_key = rsa.newkeys(1024)
public_partner = None

# Conexion con server
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("localhost", 9999))

# Verificacion con llave publica
public_partner = rsa.PublicKey.load_pkcs1(client.recv(1024))
client.send(public_key.save_pkcs1("PEM"))

def main():
    print("Bienvenido a Securechat 1.0")
    print("Escribe tu mensaje o 'salir' para terminar")
    print("Alice se ha conectado")

    send_thread = threading.Thread(target=sending_messages, args=(client,))
    recv_thread = threading.Thread(target=receiving_messages, args=(client,))
    send_thread.start()
    recv_thread.start()


# Maneja comportamiento para recibir mensajes
def receiving_messages(c):
    while True:
        msg = rsa.decrypt(c.recv(1024), private_key).decode()
        if msg == "salir":
            print("Cliente desconectado")
            c.send(rsa.encrypt("salir".encode(), public_partner))
            break
        print()
        print("Alice: " + msg)

# Maneja envio de mensajes
def sending_messages(c):
    while True:
        print()
        message = input("Yo: ")
        if message.lower() == "salir":
            c.send(rsa.encrypt(message.encode(), public_partner))
            break

        c.send(rsa.encrypt(message.encode(), public_partner))

if __name__ == "__main__":
    main()
