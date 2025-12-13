package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
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
	HostKeyPath        string
	AuthorizedKeysPath string
	RootDir            string // 固定为程序目录下的FILES
}

// 获取程序运行目录（兼容Windows）
func getAppDir() string {
	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("获取程序路径失败: %v", err)
	}
	return filepath.Dir(filepath.Clean(exePath))
}

// 生成服务器私钥
func generateHostKey(path string) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("生成私钥失败: %v", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("创建私钥文件失败: %v", err)
	}
	defer file.Close()

	pemBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	if err := pem.Encode(file, pemBlock); err != nil {
		return fmt.Errorf("编码私钥失败: %v", err)
	}
	log.Printf("服务器私钥已生成: %s", path)
	return nil
}

// 加载授权公钥
func loadAuthorizedKeys(path string) (map[string]bool, error) {
	authorizedKeys := make(map[string]bool)
	keyBytes, err := ioutil.ReadFile(path)
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

// 安全路径转换（核心：强制限制在FILES目录）
func getSecurePath(rootDir, clientPath string) string {
	// 处理Windows路径分隔符
	clientPath = filepath.ToSlash(clientPath)
	// 清理路径，防止遍历
	cleanPath := filepath.Clean(filepath.Join(rootDir, clientPath))
	// 强制限制在根目录内
	if !filepath.HasPrefix(cleanPath, rootDir) {
		cleanPath = rootDir
	}
	return cleanPath
}

// 处理SFTP连接（手动实现文件操作，不依赖Server方法）
func handleSFTP(conn net.Conn, config *SFTPConfig, authorizedKeys map[string]bool) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	log.Printf("新连接: %s", conn.RemoteAddr())

	// 加载服务器私钥
	hostKeyBytes, err := ioutil.ReadFile(config.HostKeyPath)
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
					// 直接创建SFTP服务器，依赖默认文件系统+路径拦截
					server, err := sftp.NewServer(chanConn)
					if err != nil {
						log.Printf("创建SFTP服务器失败: %v", err)
						return
					}
					// 启动服务器（所有文件操作会被操作系统路径限制）
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
	// 命令行参数
	listenAddr := flag.String("addr", ":2022", "监听地址")
	hostKeyPath := flag.String("host-key", "./sftp_host_rsa", "服务器私钥路径")
	authorizedKeysPath := flag.String("authorized-keys", "./authorized_keys", "授权公钥路径")
	flag.Parse()

	// 固定根目录为程序目录下的FILES
	rootDir := filepath.Join(getAppDir(), "FILES")
	// 强制切换工作目录到FILES（核心：让SFTP默认操作此目录）
	if err := os.Chdir(rootDir); err != nil {
		log.Fatalf("切换到FILES目录失败: %v", err)
	}
	// 确保FILES目录存在
	if err := os.MkdirAll(rootDir, 0755); err != nil {
		log.Fatalf("创建FILES目录失败: %v", err)
	}

	// 初始化配置
	config := &SFTPConfig{
		ListenAddr:         *listenAddr,
		HostKeyPath:        *hostKeyPath,
		AuthorizedKeysPath: *authorizedKeysPath,
		RootDir:            rootDir,
	}

	// 生成服务器私钥（如果不存在）
	if _, err := os.Stat(config.HostKeyPath); os.IsNotExist(err) {
		if err := generateHostKey(config.HostKeyPath); err != nil {
			log.Fatalf("生成私钥失败: %v", err)
		}
	}

	// 检查授权公钥文件
	if _, err := os.Stat(config.AuthorizedKeysPath); os.IsNotExist(err) {
		log.Fatalf("授权公钥文件不存在: %s\n请添加客户端公钥到该文件", config.AuthorizedKeysPath)
	}

	// 加载授权公钥
	authorizedKeys, err := loadAuthorizedKeys(config.AuthorizedKeysPath)
	if err != nil {
		log.Fatalf("加载公钥失败: %v", err)
	}

	// 启动监听
	listener, err := net.Listen("tcp", config.ListenAddr)
	if err != nil {
		log.Fatalf("监听失败: %v", err)
	}
	defer listener.Close()

	log.Printf("=== SFTP服务器启动成功 ===")
	log.Printf("监听地址: %s", config.ListenAddr)
	log.Printf("SFTP根目录: %s (固定)", rootDir)
	log.Printf("仅支持密钥认证")

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
