package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// SFTP服务器配置
type SFTPConfig struct {
	ListenAddr         string
	HostKeyPath        string // 服务器私钥路径（当前目录）
	AuthorizedKeysPath string // 授权公钥路径（当前目录）
	RootDir            string // SFTP操作目录（FILES）
}

// 获取程序运行目录（兼容Windows）
func getAppDir() string {
	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("获取程序路径失败: %v", err)
	}
	return filepath.Dir(filepath.Clean(exePath))
}

// 生成服务器私钥（存当前目录，非FILES）
func generateHostKey(path string) error {
	// 确保私钥路径是当前目录（防止被切换到FILES）
	path, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("获取私钥绝对路径失败: %v", err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("生成私钥失败: %v", err)
	}

	// 创建私钥文件（当前目录）
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("创建私钥文件失败: %v", err)
	}
	defer file.Close()

	pemBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	if err := pem.Encode(file, pemBlock); err != nil {
		return fmt.Errorf("编码私钥失败: %v", err)
	}
	log.Printf("服务器私钥已生成（当前目录）: %s", path)
	return nil
}

// 加载授权公钥（当前目录的authorized_keys）
func loadAuthorizedKeys(path string) (map[string]bool, error) {
	// 确保公钥文件路径是当前目录
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("获取公钥绝对路径失败: %v", err)
	}

	authorizedKeys := make(map[string]bool)
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取公钥失败: %v", err)
	}

	for len(keyBytes) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(keyBytes)
		if err != nil {
			keyBytes = rest
			continue
		}
		authorizedKeys[string(pubKey.Marshal())] = true
		keyBytes = rest
	}
	log.Printf("加载授权公钥数量: %d", len(authorizedKeys))
	return authorizedKeys, nil
}

// 处理SFTP连接
func handleSFTP(conn net.Conn, config *SFTPConfig, authorizedKeys map[string]bool) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	log.Printf("新连接: %s", conn.RemoteAddr())

	// 加载服务器私钥（当前目录，不受工作目录切换影响）
	hostKeyBytes, err := os.ReadFile(config.HostKeyPath)
	if err != nil {
		log.Printf("读取服务器私钥失败: %v", err)
		return
	}
	hostKey, err := ssh.ParsePrivateKey(hostKeyBytes)
	if err != nil {
		log.Printf("解析私钥失败: %v", err)
		return
	}

	// SSH服务器配置
	sshConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			if authorizedKeys[string(pubKey.Marshal())] {
				log.Printf("公钥认证成功: %s", conn.RemoteAddr())
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("未授权的公钥")
		},
		PasswordCallback: func(_ ssh.ConnMetadata, _ []byte) (*ssh.Permissions, error) {
			return nil, fmt.Errorf("禁用密码登录")
		},
	}
	sshConfig.AddHostKey(hostKey)

	// SSH握手
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, sshConfig)
	if err != nil {
		log.Printf("SSH握手失败: %v", err)
		return
	}
	defer sshConn.Close()

	// 设置会话超时
	if netConn, ok := sshConn.Conn.(net.Conn); ok {
		netConn.SetDeadline(time.Now().Add(2 * time.Hour))
	}

	// 丢弃无关请求
	go ssh.DiscardRequests(reqs)

	// 处理Session通道
	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			newChan.Reject(ssh.UnknownChannelType, "仅支持session通道")
			continue
		}

		chanConn, reqs, err := newChan.Accept()
		if err != nil {
			log.Printf("接受通道失败: %v", err)
			continue
		}
		defer chanConn.Close()

		// 处理SFTP子系统请求
		go func(reqs <-chan *ssh.Request) {
			for req := range reqs {
				if req.Type == "subsystem" && len(req.Payload) > 4 && string(req.Payload[4:]) == "sftp" {
					req.Reply(true, nil)
					// 创建SFTP服务器（操作目录为FILES）
					server, err := sftp.NewServer(chanConn)
					if err != nil {
						log.Printf("创建SFTP服务器失败: %v", err)
						return
					}
					// 启动服务器（文件操作限制在FILES目录）
					if err := server.Serve(); err != nil && err != io.EOF {
						log.Printf("SFTP会话异常: %v", err)
					}
					return
				}
				req.Reply(false, nil)
			}
		}(reqs)
	}
}

func main() {
	// 命令行参数（密钥文件默认当前目录）
	listenAddr := flag.String("addr", ":2022", "监听地址")
	hostKeyPath := flag.String("host-key", "./sftp_host_rsa.pem", "服务器私钥路径（当前目录）")
	authorizedKeysPath := flag.String("authorized-keys", "./authorized_keys", "授权公钥路径（当前目录）")
	flag.Parse()

	// 1. 初始化路径（核心区分：密钥存当前目录，操作目录是FILES）
	appDir := getAppDir()                                  // 程序运行目录
	operateDir := filepath.Join(appDir, "FILES")           // SFTP操作目录（FILES）
	hostKeyAbsPath, _ := filepath.Abs(*hostKeyPath)        // 私钥绝对路径（当前目录）
	authKeyAbsPath, _ := filepath.Abs(*authorizedKeysPath) // 公钥绝对路径（当前目录）

	// 2. 确保FILES操作目录存在（仅用于文件操作）
	if err := os.MkdirAll(operateDir, 0755); err != nil {
		log.Fatalf("创建FILES操作目录失败: %v", err)
	}

	// 3. 切换工作目录到FILES（仅影响文件操作，不影响密钥文件）
	if err := os.Chdir(operateDir); err != nil {
		log.Fatalf("切换到FILES操作目录失败: %v", err)
	}

	// 4. 初始化配置
	config := &SFTPConfig{
		ListenAddr:         *listenAddr,
		HostKeyPath:        hostKeyAbsPath, // 私钥绝对路径（当前目录）
		AuthorizedKeysPath: authKeyAbsPath, // 公钥绝对路径（当前目录）
		RootDir:            operateDir,     // FILES操作目录
	}

	// 5. 生成服务器私钥（仅当不存在时，存当前目录）
	if _, err := os.Stat(config.HostKeyPath); os.IsNotExist(err) {
		if err := generateHostKey(config.HostKeyPath); err != nil {
			log.Fatalf("生成私钥失败: %v", err)
		}
	}

	// 6. 检查授权公钥文件（当前目录）
	if _, err := os.Stat(config.AuthorizedKeysPath); os.IsNotExist(err) {
		log.Fatalf("授权公钥文件不存在: %s\n请添加客户端公钥到该文件（当前目录）", config.AuthorizedKeysPath)
	}

	// 7. 加载授权公钥（当前目录）
	authorizedKeys, err := loadAuthorizedKeys(config.AuthorizedKeysPath)
	if err != nil {
		log.Fatalf("加载公钥失败: %v", err)
	}

	// 8. 启动监听
	listener, err := net.Listen("tcp", config.ListenAddr)
	if err != nil {
		log.Fatalf("监听失败: %v", err)
	}
	defer listener.Close()

	// 打印启动信息（明确区分密钥目录和操作目录）
	log.Printf("=== SFTP服务器启动成功 ===")
	log.Printf("监听地址: %s", config.ListenAddr)
	log.Printf("服务器私钥: %s（当前目录）", config.HostKeyPath)
	log.Printf("授权公钥: %s（当前目录）", config.AuthorizedKeysPath)
	log.Printf("SFTP操作目录: %s（仅文件操作）", config.RootDir)
	log.Printf("仅支持密钥认证，禁用密码登录")

	// 并发处理连接
	var wg sync.WaitGroup
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("接受连接失败: %v", err)
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			handleSFTP(conn, config, authorizedKeys)
		}()
	}
}
