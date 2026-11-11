# Lilium

![](/lilium.jpg?raw=true)

## Cloning

````
$ git clone https://github.com/DhiLaurent/Lilium
````

## Go Compilation

````
$ cd Lilium/go
````

````
$ make
````

## Python Compilation

[!] Save lilium with pyw extension

### Compile .pyw to exe

````
python -m PyInstaller --onefile lilium.pyw --windowed --icon=C:\Users\User\icon.ico
````

### Download upx packer
````
https://github.com/upx/upx
````

### Compact exe with upx packer
````
> upx.exe --best --lzma --force lilium.exe
````

### Set up Server Side

Create certificate
````
$ openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/C=BR/ST=State/L=City/O=Organization/OU=Unit/CN=example.com/emailAddress=email@example.com"\n
````

````
$ python3 server.py # python
````

````
$ ./server # go
````

