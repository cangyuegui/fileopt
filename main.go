package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

/* ================= 工具：路径隔离 ================= */
// 核心：所有客户端路径 → FILES 内真实路径
func secureJoin(root, path string) (string, error) {
	// 1. 清理请求路径（去除 ../、./ 等冗余部分）
	cleanPath := filepath.Clean(path)
	// 2. 拼接根目录和请求路径
	fullPath := filepath.Join(root, cleanPath)
	// 3. 获取根目录的绝对路径（用于后续校验）
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("获取根目录绝对路径失败: %w", err)
	}

	// 4. 处理路径：存在则解析软链接，不存在则直接用拼接路径
	var finalPath string
	_, err = os.Stat(fullPath)
	if err == nil {
		// 路径存在：解析所有软链接
		realPath, err := filepath.EvalSymlinks(fullPath)
		if err != nil {
			return "", fmt.Errorf("解析软链接失败: %w", err)
		}
		finalPath = realPath
	} else if os.IsNotExist(err) {
		// 路径不存在：转为绝对路径后使用
		absFullPath, err := filepath.Abs(fullPath)
		if err != nil {
			return "", fmt.Errorf("获取绝对路径失败: %w", err)
		}
		finalPath = absFullPath
	} else {
		return "", fmt.Errorf("检查路径失败: %w", err)
	}

	// ========== 核心修复：Windows 大小写不敏感处理 ==========
	// 统一转为小写（仅对 Windows 生效，Linux/macOS 保持大小写敏感）
	var (
		compareRoot     = absRoot
		compareFinal    = finalPath
		compareRootWith = filepath.Join(absRoot, string(filepath.Separator))
	)
	if filepath.Separator == '\\' { // 判断是否为 Windows 系统
		compareRoot = strings.ToLower(absRoot)
		compareFinal = strings.ToLower(finalPath)
		compareRootWith = strings.ToLower(compareRootWith)
	}

	// 5. 安全校验：最终路径必须在根目录范围内
	// 两种情况都要匹配：
	// - 完全匹配根目录（如 root=C:\test，finalPath=C:\test）
	// - 匹配根目录+分隔符（如 root=C:\test，finalPath=C:\test\file.txt）
	if !strings.HasPrefix(compareFinal, compareRoot) && !strings.HasPrefix(compareFinal, compareRootWith) {
		return "", fmt.Errorf("access denied: path outside root directory (requested: %s, root: %s)", finalPath, absRoot)
	}

	return finalPath, nil
}

/* ================= ListerAt 实现（老版本兼容） ================= */

type fileInfoLister struct {
	files []os.FileInfo
}

func (l *fileInfoLister) ListAt(dst []os.FileInfo, offset int64) (int, error) {
	if offset >= int64(len(l.files)) {
		return 0, io.EOF
	}

	n := copy(dst, l.files[offset:])
	if offset+int64(n) >= int64(len(l.files)) {
		return n, io.EOF
	}
	return n, nil
}

/* ================= SFTP Handler ================= */

type SecureHandler struct {
	root string
}

func NewSecureHandler(root string) *SecureHandler {
	r, err := filepath.Abs(root)
	if err != nil {
		panic(err)
	}
	return &SecureHandler{root: r}
}

func (h *SecureHandler) Fileread(req *sftp.Request) (io.ReaderAt, error) {
	p, err := secureJoin(h.root, req.Filepath)
	if err != nil {
		return nil, err
	}
	return os.Open(p)
}

func (h *SecureHandler) Filewrite(req *sftp.Request) (io.WriterAt, error) {
	p, err := secureJoin(h.root, req.Filepath)
	if err != nil {
		return nil, err
	}
	return os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
}

func (h *SecureHandler) Filecmd(req *sftp.Request) error {
	p, err := secureJoin(h.root, req.Filepath)
	if err != nil {
		return err
	}

	switch req.Method {
	case "Remove":
		return os.Remove(p)
	case "Mkdir":
		return os.Mkdir(p, 0755)
	case "Rmdir":
		return os.Remove(p)
	case "Rename":
		t, err := secureJoin(h.root, req.Target)
		if err != nil {
			return err
		}
		return os.Rename(p, t)
	case "Chmod":
		// 这里直接用 Mode
		return os.Chmod(p, os.FileMode(req.Attributes().Mode))
	default:
		return errors.New("unsupported filecmd")
	}
}

func (h *SecureHandler) Filelist(req *sftp.Request) (sftp.ListerAt, error) {
	p, err := secureJoin(h.root, req.Filepath)
	if err != nil {
		return nil, err
	}

	var infos []os.FileInfo

	switch req.Method {
	case "List":
		ents, err := os.ReadDir(p)
		if err != nil {
			return nil, err
		}
		for _, e := range ents {
			i, err := e.Info()
			if err == nil {
				infos = append(infos, i)
			}
		}
	case "Stat":
		i, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		infos = []os.FileInfo{i}
	default:
		return nil, errors.New("unsupported list method")
	}

	return &fileInfoLister{files: infos}, nil
}

/* ================= SSH / SFTP Server ================= */

// 引入SSH/SFTP依赖

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

// 生成客户端RSA密钥对 + 自签名证书（新增功能）
func generateClientKey(clientKeyPath string) error {
	// 生成客户端2048位RSA私钥
	clientPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("生成客户端私钥失败: %v", err)
	}

	// 1. 保存客户端私钥（client_rsa）
	privKeyFile, err := os.OpenFile(clientKeyPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("创建客户端私钥文件失败: %v", err)
	}
	defer privKeyFile.Close()

	privPemBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientPrivKey)}
	if err := pem.Encode(privKeyFile, privPemBlock); err != nil {
		return fmt.Errorf("编码客户端私钥失败: %v", err)
	}

	// 2. 生成客户端公钥（client_rsa.pub）
	clientPubKey, err := ssh.NewPublicKey(&clientPrivKey.PublicKey)
	if err != nil {
		return fmt.Errorf("生成客户端公钥失败: %v", err)
	}
	pubKeyPath := clientKeyPath + ".pub"
	pubKeyFile, err := os.OpenFile(pubKeyPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("创建客户端公钥文件失败: %v", err)
	}
	defer pubKeyFile.Close()

	if _, err := pubKeyFile.Write(ssh.MarshalAuthorizedKey(clientPubKey)); err != nil {
		return fmt.Errorf("写入客户端公钥失败: %v", err)
	}

	// 3. 生成客户端自签名证书（client_rsa.crt）
	crtPath := clientKeyPath + ".crt"
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "SFTP Client"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 有效期1年
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &clientPrivKey.PublicKey, clientPrivKey)
	if err != nil {
		return fmt.Errorf("生成客户端证书失败: %v", err)
	}

	crtFile, err := os.OpenFile(crtPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("创建客户端证书文件失败: %v", err)
	}
	defer crtFile.Close()

	crtPemBlock := &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}
	if err := pem.Encode(crtFile, crtPemBlock); err != nil {
		return fmt.Errorf("编码客户端证书失败: %v", err)
	}

	// 打印生成结果
	log.Printf("=== 客户端密钥/证书生成完成 ===")
	log.Printf("客户端私钥: %s（当前目录）", clientKeyPath)
	log.Printf("客户端公钥: %s（可添加到authorized_keys）", pubKeyPath)
	log.Printf("客户端证书: %s（有效期1年）", crtPath)
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
		NoClientAuth:                false,
		KeyboardInteractiveCallback: nil,
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
					server := sftp.NewRequestServer(
						chanConn,
						sftp.Handlers{
							FileGet:  NewSecureHandler(config.RootDir),
							FilePut:  NewSecureHandler(config.RootDir),
							FileCmd:  NewSecureHandler(config.RootDir),
							FileList: NewSecureHandler(config.RootDir),
						},
					)
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
	// 新增：-client_key 参数（指定客户端密钥生成路径，默认 ./client_rsa）
	clientKeyGen := flag.String("client_key", "", "生成客户端密钥/证书（指定路径，如 ./client_rsa）")

	// 原有命令行参数（密钥文件默认当前目录）
	listenAddr := flag.String("addr", ":2022", "监听地址")
	hostKeyPath := flag.String("host-key", "./sftp_host_rsa.pem", "服务器私钥路径（当前目录）")
	authorizedKeysPath := flag.String("authorized-keys", "./client_rsa.pub", "授权公钥路径（当前目录）")
	flag.Parse()

	// 核心逻辑1：如果指定了 -client_key，先生成客户端密钥/证书，然后退出
	if *clientKeyGen != "" {
		clientKeyAbsPath, err := filepath.Abs(*clientKeyGen)
		if err != nil {
			log.Fatalf("获取客户端密钥路径失败: %v", err)
		}
		if err := generateClientKey(clientKeyAbsPath); err != nil {
			log.Fatalf("生成客户端密钥/证书失败: %v", err)
		}
		// 生成完成后退出，不启动SFTP服务器
		return
	}

	// 核心逻辑2：未指定 -client_key，启动SFTP服务器
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
