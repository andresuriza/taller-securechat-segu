import hashlib
import socket
import sys
import struct
import threading

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Constantes de conexion
class ConnectionDetails:
    def __init__(self, PORT, ME, PEER):
        self.HOST = "localhost"
        self.PORT = PORT
        self.OAEP = padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )
        self.ME = ME
        self.PEER = PEER

# Canal seguro SHA256
class SecureChannel:
    def __init__(self, key, my_role, peer_role):
        self.aead = AESGCM(key)
        self.my_role = my_role
        self.peer_role = peer_role
        self.send_counter = 0
        self.recv_counter = -1
        self.lock = threading.Lock()

    # Devuelve el plaintext
    def decrypt(self, data):
        if len(data) < 12 + 16:
            raise ValueError("mensaje demasiado corto")
        nonce, ct_and_tag = data[:12], data[12:]
        if nonce[:4] != self.peer_role:
            raise ValueError("nonce con prefijo de rol invalido")
        (counter,) = struct.unpack(">Q", nonce[4:])
        if counter <= self.recv_counter:
            raise ValueError("nonce repetido (posible replay)")
        try:
            plaintext = self.aead.decrypt(nonce, ct_and_tag, self.peer_role)
        except InvalidTag:
            raise ValueError("authentication tag invalido")
        self.recv_counter = counter
        return plaintext

    # Cifrado de plaintext a enviar
    def encrypt(self, plaintext):
        with self.lock:
            nonce = self.my_role + struct.pack(">Q", self.send_counter)
            self.send_counter += 1
        ct_and_tag = self.aead.encrypt(nonce, plaintext, self.my_role)

        # nonce(12) | ciphertext | tag(16)
        return nonce + ct_and_tag

def main():
    this_conn = ConnectionDetails(9999, "Alice", "Bob")

    print("Bienvenido a Securechat 1.0")
    print(f"Usuario: {this_conn.ME}")

    # La llave privada nunca sale de este proceso
    private_key = generate_keypair()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((this_conn.HOST, this_conn.PORT))
    server.listen(1)
    print(f"Esperando conexion en {this_conn.HOST}:{this_conn.PORT}...")
    conn, _ = server.accept()
    server.close()
    print(f"{this_conn.PEER} se ha conectado")

    # Handshake: intercambio de llaves publicas
    client_pkey = exchange_public_keys(conn, private_key, send_first=True)

    # Clave de sesion aleatoria (256 bits), cifrada con RSA-OAEP hacia peer
    session_key = AESGCM.generate_key(bit_length=256)
    send_frame(conn, client_pkey.encrypt(session_key, this_conn.OAEP))
    print("[HANDSHAKE] Clave de sesion generada y enviada cifrada con RSA-OAEP")

    channel = SecureChannel(session_key, my_role=b"ALIC", peer_role=b"BOB_")

    # Confirmacion: Peer debe demostrar que obtuvo la misma clave
    try:
        confirm = channel.decrypt(recv_frame(conn))
    except ValueError as e:
        print(f"Error: handshake fallido ({e})")
        sys.exit(1)
    if confirm != b"hello":
        print("Error: handshake fallido")
        sys.exit(1)

    print("[SESION SEGURA ESTABLECIDA] AES-256-GCM activo")
    print(f"Conectado con {this_conn.PEER}. Escribe tu mensaje o 'salir' para terminar")
    chat(conn, channel, this_conn.ME, this_conn.PEER)

def chat(sock, channel, my_name, peer_name):
    done = threading.Event()

    def sender():
        try:
            while not done.is_set():
                msg = input(f"\n{my_name} > ")
                if done.is_set():
                    break
                if not msg:
                    continue
                print(f"[LOCAL]     plaintext : {msg}")
                frame = channel.encrypt(msg.encode())
                print(f"[ENVIADO]   ciphertext: {frame.hex()}")
                send_frame(sock, frame)
                if msg.strip().lower() == "salir":
                    print("[SESION] Has terminado la sesion.")
                    done.set()
                    break
        except (EOFError, OSError):
            done.set()
        finally:
            try:
                sock.shutdown(2)
            except OSError:
                pass

    threading.Thread(target=sender, daemon=True).start()

    try:
        while not done.is_set():
            frame = recv_frame(sock)
            print(f"\n[RECIBIDO]  ciphertext: {frame.hex()}")
            try:
                plaintext = channel.decrypt(frame).decode()
            except ValueError as e:
                print(f"[RECHAZADO] Mensaje descartado: {e}")
                continue
            print(f"[VERIFICADO] plaintext recuperado de {peer_name}: {plaintext}")
            if plaintext.strip().lower() == "salir":
                print(f"[SESION] {peer_name} ha terminado la sesion.")
                done.set()
                break
            print(f"\n{my_name} > ", end="", flush=True)
    except (ConnectionError, OSError):
        if not done.is_set():
            print("\n[SESION] Conexion cerrada.")
    finally:
        done.set()
        sock.close()

def exchange_public_keys(sock, private_key, send_first):
    mine = public_pem(private_key)
    if send_first:
        send_frame(sock, mine)
        theirs = recv_frame(sock)
    else:
        theirs = recv_frame(sock)
        send_frame(sock, mine)
    peer_key = serialization.load_pem_public_key(theirs)
    print(f"[HANDSHAKE] Huella de mi llave publica : {fingerprint(mine)}")
    print(f"[HANDSHAKE] Huella de llave publica peer: {fingerprint(theirs)}")
    return peer_key

def fingerprint(pem):
    return hashlib.sha256(pem).hexdigest()[:16]

# Claves asimetricas
def generate_keypair():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def public_pem(private_key):
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Conexion cerrada por el otro extremo")
        buf += chunk
    return buf

def recv_frame(sock):
    (length,) = struct.unpack(">I", recv_exact(sock, 4))
    return recv_exact(sock, length)

# Transporte con framing (4 bytes con longitud)
def send_frame(sock, data):
    sock.sendall(struct.pack(">I", len(data)) + data)


if __name__ == "__main__":
    main()
