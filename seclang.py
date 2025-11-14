import socket
import os
import threading
import json
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

# QR code + scanner
import qrcode
from PIL import Image, ImageTk
import cv2
from pyzbar.pyzbar import decode

PORT = 5001
CHUNK_SIZE = 1024 * 1024
KEY_LEN = 32


# ---------- crypto helpers ----------
def derive_shared_key(local_private: X25519PrivateKey, peer_public_bytes: bytes) -> bytes:
    peer_pub = X25519PublicKey.from_public_bytes(peer_public_bytes)
    shared = local_private.exchange(peer_pub)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=None,
        info=b"darkdoc file transfer",
    )
    return hkdf.derive(shared)


def encrypt_chunk(plaintext: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct


def decrypt_chunk(enc: bytes, key: bytes) -> bytes:
    nonce = enc[:12]
    ct = enc[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)


# ---------- networking helpers ----------
def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly")
        buf += chunk
    return buf


def send_prefixed(sock: socket.socket, data: bytes):
    sock.sendall(len(data).to_bytes(4, "big") + data)


def recv_prefixed(sock: socket.socket) -> bytes:
    length = int.from_bytes(recv_exact(sock, 4), "big")
    return recv_exact(sock, length)


# ---------- QR helpers ----------
def show_qr_code(ip, port):
    url = f"darkdoc://{ip}:{port}"
    qr = qrcode.make(url)

    qr_window = tk.Toplevel()
    qr_window.title("Scan this QR on Receiver")
    qr_img = ImageTk.PhotoImage(qr)
    label = tk.Label(qr_window, image=qr_img)
    label.image = qr_img
    label.pack(padx=10, pady=10)

    info = tk.Label(qr_window, text=url, font=("Consolas", 10))
    info.pack(pady=5)


def scan_qr_code():
    cap = cv2.VideoCapture(0)
    server_ip, server_port = None, None

    while True:
        ret, frame = cap.read()
        if not ret:
            break
        for code in decode(frame):
            data = code.data.decode("utf-8")
            if data.startswith("darkdoc://"):
                parts = data.replace("darkdoc://", "").split(":")
                server_ip = parts[0]
                server_port = int(parts[1])
                cap.release()
                cv2.destroyAllWindows()
                return server_ip, server_port

        cv2.imshow("Scan QR - Press Q to cancel", frame)
        if cv2.waitKey(1) & 0xFF == ord("q"):
            break

    cap.release()
    cv2.destroyAllWindows()
    return None, None


# ---------- send / receive logic ----------
def threaded_send_file(filename, update_ui_callback=None):
    try:
        if not os.path.exists(filename):
            raise FileNotFoundError("File does not exist")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("0.0.0.0", PORT))
            s.listen(1)

            local_ip = socket.gethostbyname(socket.gethostname())
            if update_ui_callback:
                update_ui_callback(f"Server on {local_ip}:{PORT}, waiting for connection...")

            # show QR code in popup
            root = tk.Tk()
            root.withdraw()
            root.after(0, show_qr_code, local_ip, PORT)
            threading.Thread(target=root.mainloop, daemon=True).start()

            conn, addr = s.accept()
            with conn:
                if update_ui_callback:
                    update_ui_callback(f"Connected by {addr}")

                # key exchange
                local_priv = X25519PrivateKey.generate()
                local_pub = local_priv.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
                send_prefixed(conn, local_pub)
                peer_pub_bytes = recv_prefixed(conn)
                key = derive_shared_key(local_priv, peer_pub_bytes)

                # send encrypted metadata
                filesize = os.path.getsize(filename)
                meta = json.dumps({"name": os.path.basename(filename), "size": filesize}).encode()
                send_prefixed(conn, encrypt_chunk(meta, key))

                # send file
                with open(filename, "rb") as f:
                    sent = 0
                    while True:
                        chunk = f.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        send_prefixed(conn, encrypt_chunk(chunk, key))
                        sent += len(chunk)
                        if update_ui_callback:
                            update_ui_callback(f"Sent {sent}/{filesize} bytes")

                if update_ui_callback:
                    update_ui_callback(f"✅ File '{os.path.basename(filename)}' sent successfully.")
    except Exception as e:
        if update_ui_callback:
            update_ui_callback(f"Error: {e}")


def threaded_receive_file(server_ip, update_ui_callback=None, ask_save_path_callback=None):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((server_ip, PORT))
            if update_ui_callback:
                update_ui_callback(f"Connected to {server_ip}:{PORT}")

            # key exchange
            server_pub = recv_prefixed(s)
            local_priv = X25519PrivateKey.generate()
            local_pub = local_priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            send_prefixed(s, local_pub)
            key = derive_shared_key(local_priv, server_pub)

            # metadata
            enc_meta = recv_prefixed(s)
            meta = json.loads(decrypt_chunk(enc_meta, key).decode())
            filename = meta.get("name", "received_file")
            filesize = int(meta.get("size", 0))

            if update_ui_callback:
                update_ui_callback(f"Receiving {filename} ({filesize} bytes)")

            default_save = os.path.join(os.getcwd(), "received_" + filename)
            save_path = filedialog.asksaveasfilename(initialfile="received_" + filename,
                                                     initialdir=os.getcwd())
            if not save_path:
                if update_ui_callback:
                    update_ui_callback("Receive canceled.")
                return

            received = 0
            with open(save_path, "wb") as f:
                while received < filesize:
                    enc_chunk = recv_prefixed(s)
                    chunk = decrypt_chunk(enc_chunk, key)
                    f.write(chunk)
                    received += len(chunk)
                    if update_ui_callback:
                        update_ui_callback(f"Received {received}/{filesize} bytes")

            if update_ui_callback:
                update_ui_callback(f"✅ File saved to {save_path}")
    except Exception as e:
        if update_ui_callback:
            update_ui_callback(f"Error: {e}")


# ---------- GUI ----------
def start_send_ui(status_var):
    filename = filedialog.askopenfilename(title="Select a file to send")
    if not filename:
        return
    t = threading.Thread(target=threaded_send_file,
                         args=(filename, lambda msg: status_var.set(msg)),
                         daemon=True)
    t.start()


def start_receive_ui(root, status_var):
    server_ip = simpledialog.askstring("DarkDoc", "Enter Server IP:")
    if not server_ip:
        return
    t = threading.Thread(target=threaded_receive_file,
                         args=(server_ip, lambda msg: status_var.set(msg), None),
                         daemon=True)
    t.start()


def handle_qr_receive(root, status_var):
    ip, port = scan_qr_code()
    if ip:
        status_var.set(f"Scanned IP: {ip}:{port}")
        t = threading.Thread(target=threaded_receive_file,
                             args=(ip, lambda msg: status_var.set(msg), None),
                             daemon=True)
        t.start()
    else:
        messagebox.showerror("DarkDoc", "No QR code detected.")


def main():
    root = tk.Tk()
    root.title("DarkDoc P2P (Encrypted + QR)")
    root.geometry("450x260")

    lbl = tk.Label(root, text="DarkDoc P2P — Encrypted (LAN)", font=("Consolas", 14, "bold"))
    lbl.pack(pady=12)

    status_var = tk.StringVar(value="Ready")

    btn_frame = tk.Frame(root)
    btn_frame.pack(pady=8)

    send_btn = tk.Button(btn_frame, text="📤 Send File", width=20,
                         command=lambda: start_send_ui(status_var))
    send_btn.grid(row=0, column=0, padx=8, pady=6)

    recv_btn = tk.Button(btn_frame, text="📥 Receive File", width=20,
                         command=lambda: start_receive_ui(root, status_var))
    recv_btn.grid(row=0, column=1, padx=8, pady=6)

    scan_btn = tk.Button(btn_frame, text="📷 Scan QR", width=43,
                         command=lambda: handle_qr_receive(root, status_var))
    scan_btn.grid(row=1, column=0, columnspan=2, pady=6)

    status_label = tk.Label(root, textvariable=status_var, font=("Consolas", 10), fg="#00cc66")
    status_label.pack(pady=18)

    hint = tk.Label(root, text="Both devices must be on the same LAN. Allow firewall if needed.",
                    font=("Arial", 8))
    hint.pack(side="bottom", pady=6)

    root.mainloop()


if __name__ == "__main__":
    main()