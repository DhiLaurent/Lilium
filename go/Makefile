.PHONY: all server client clean

all: server client

server:
        @echo "[+] Compilando o Servidor..."
        go build -o bin/server cmd/server.go
        GOOS=windows GOARCH=amd64 go build -o bin/server.exe cmd/server.go

client:
        @echo "[+] Compilando os Agentes..."
        GOOS=linux GOARCH=amd64 go build -o bin/client cmd/client_linux.go
        GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -H=windowsgui" -o bin/client.exe cmd/client_windows.go

clean:
        rm -rf bin/
