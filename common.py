import hashlib
import struct
import threading

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = "localhost"
PORT = 9999

OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


# ---------- Transporte con framing (prefijo de 4 bytes con la longitud) ----------

def send_frame(sock, data):
    sock.sendall(struct.pack(">I", len(data)) + data)


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


# ---------- Claves asimetricas ----------

def generate_keypair():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def public_pem(private_key):
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def fingerprint(pem):
    return hashlib.sha256(pem).hexdigest()[:16]


def exchange_public_keys(sock, private_key, send_first):
    """Intercambia llaves publicas (solo la publica viaja por el socket)."""
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


# ---------- Canal seguro AES-256-GCM ----------

class SecureChannel:
    """AES-256-GCM. Nonce de 12 bytes = prefijo de rol (4) + contador (8).

    Cada rol usa un prefijo distinto y un contador creciente, asi un nonce
    nunca se repite bajo la misma clave. El receptor exige contadores
    estrictamente crecientes (rechaza repeticiones). El rol del emisor va
    como AAD para impedir que un mensaje se refleje hacia su emisor.
    """

    def __init__(self, key, my_role, peer_role):
        self.aead = AESGCM(key)
        self.my_role = my_role      # b"ALIC" o b"BOB_"
        self.peer_role = peer_role
        self.send_counter = 0
        self.recv_counter = -1
        self.lock = threading.Lock()

    def encrypt(self, plaintext):
        with self.lock:
            nonce = self.my_role + struct.pack(">Q", self.send_counter)
            self.send_counter += 1
        ct_and_tag = self.aead.encrypt(nonce, plaintext, self.my_role)
        return nonce + ct_and_tag  # nonce(12) || ciphertext || tag(16)

    def decrypt(self, data):
        """Devuelve el plaintext, o lanza ValueError si no es valido."""
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


# ---------- Chat ----------

def chat(sock, channel, my_name, peer_name):
    """Receptor en el hilo principal, emisor en un hilo aparte."""
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
