package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
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
	"sync/atomic"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// ================= 全局IP黑名单相关 =================
// IP失败次数记录（线程安全）
var ipFailMap = sync.Map{}

// IP黑名单（线程安全）
var ipBlacklist = sync.Map{}

// 黑名单文件路径
var blacklistFile string

// 日志文件路径
var logFile string

// 黑名单计数（原子操作，用于攻击检测）
var blackIPCount int64 = 0

// 配置常量
const (
	maxAuthTriesPerIP = 3  // 单IP最大失败次数
	blacklistMaxCount = 50 // 黑名单最大IP数（超过则自裁）
	blacklistDirName  = "his_store_bak"
	blacklistFileName = "sftp_blackip.txt"
	logFileName       = "sftp.log"
	selfDestructMsgCn = "遭遇攻击，自裁保护！"
	selfDestructMsgEn = "Under attack, self-destruct protection!"
)

// ================= IP黑名单核心功能 =================
// getClientIP 提取客户端IP
func getClientIP(remoteAddr string) string {
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return ip
}

// recordIPFail 记录IP失败次数，超过阈值则加入黑名单
func recordIPFail(ip string) bool {
	// 1. 先检查是否已在黑名单（已拉黑则直接返回，无需处理）
	if _, exists := ipBlacklist.Load(ip); exists {
		return true
	}

	// 2. 核心修正：先+1，再判断是否拉黑（统计准确）
	val, _ := ipFailMap.LoadOrStore(ip, 0) // 初始值设为0，保证第一次+1后为1
	count := val.(int) + 1                 // 先+1，得到本次失败后的总次数
	ipFailMap.Store(ip, count)             // 更新失败次数
	logMsg := fmt.Sprintf(
		"[%s] IP失败次数记录 | IP: %s | 本次失败后总次数: %d | 拉黑阈值: %d",
		time.Now().Format(time.RFC3339),
		ip,
		count,
		maxAuthTriesPerIP,
	)
	logToFile(logMsg)

	// 3. 判断是否达到拉黑阈值
	if count >= maxAuthTriesPerIP {
		// 3.1 加入黑名单
		ipBlacklist.Store(ip, time.Now().Format(time.RFC3339))
		newCount := atomic.AddInt64(&blackIPCount, 1)

		// 3.2 关键：拉黑后移除错误列表（释放内存，后续无需处理）
		ipFailMap.Delete(ip)

		// 3.3 保存黑名单到文件（原函数传了ip参数，需同步修改saveBlacklist）
		saveBlacklist(ip)

		// 3.4 检查是否触发自裁保护
		if newCount >= blacklistMaxCount {
			logMsg := fmt.Sprintf("[%s] %s | %s", time.Now().Format(time.RFC3339), selfDestructMsgCn, selfDestructMsgEn)
			logToFile(logMsg)
			fmt.Printf("%s\n", logMsg)
			os.Exit(1) // 自裁退出
		}
		return true
	}

	// 未达到阈值，返回false
	return false
}

// saveBlacklist 将黑名单保存到文件（Base64编码）
func saveBlacklist(ip string) {
	// 创建目录
	if err := os.MkdirAll(filepath.Dir(blacklistFile), 0755); err != nil {
		logToFile(fmt.Sprintf("创建黑名单目录失败: %v", err))
		return
	}

	// Base64编码
	encoded := base64.StdEncoding.EncodeToString([]byte(ip))

	// 写入文件
	f, err := os.OpenFile(blacklistFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		logToFile(fmt.Sprintf("打开黑名单文件失败: %v", err))
		return
	}
	defer f.Close()

	// 写入内容（追加）
	if _, err := f.WriteString(encoded + "\n"); err != nil {
		logToFile(fmt.Sprintf("追加黑名单失败: %v", err))
	} else {
		logToFile(fmt.Sprintf("追加黑名单成功，当前黑名单总数: %d", blackIPCount))
	}
}

func loadBlacklist() {
	// 检查文件是否存在
	if _, err := os.Stat(blacklistFile); os.IsNotExist(err) {
		logToFile("黑名单文件不存在，跳过加载")
		return
	}

	// 打开文件（只读模式）
	file, err := os.Open(blacklistFile)
	if err != nil {
		logToFile(fmt.Sprintf("打开黑名单文件失败: %v", err))
		return
	}
	defer file.Close()

	// 按行读取文件
	scanner := bufio.NewScanner(file)
	count := 0            // 成功加载的IP数
	failCount := 0        // 解码失败的行数
	invalidLineCount := 0 // 无效行（空行/格式错误）数

	for scanner.Scan() {
		// 读取当前行并去除首尾空格/换行
		line := strings.TrimSpace(scanner.Text())

		// 跳过空行
		if line == "" {
			invalidLineCount++
			continue
		}

		// 每行单独进行Base64解码（解码结果即为拉黑IP）
		decodedIP, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			logToFile(fmt.Sprintf("行内容Base64解码失败 | 行内容: %s | 错误: %v", line, err))
			failCount++
			continue
		}

		// 解码后的IP格式校验（可选：确保是合法IP）
		ip := string(decodedIP)
		if net.ParseIP(ip) == nil {
			logToFile(fmt.Sprintf("解码后非合法IP | 行内容: %s | 解码结果: %s", line, ip))
			invalidLineCount++
			continue
		}

		// 将IP存入黑名单Map（拉黑时间设为加载时的时间，或保留原逻辑）
		ipBlacklist.Store(ip, time.Now().Format(time.RFC3339))
		count++
	}

	// 检查读取过程中是否出错
	if err := scanner.Err(); err != nil {
		logToFile(fmt.Sprintf("按行读取黑名单文件失败: %v", err))
	}

	// 更新黑名单原子计数
	atomic.StoreInt64(&blackIPCount, int64(count))

	// 打印加载统计日志
	logToFile(fmt.Sprintf(
		"黑名单加载完成 | 成功加载IP数: %d | 解码失败行数: %d | 无效行数: %d",
		count, failCount, invalidLineCount,
	))
}

// logToFile 写入日志到文件
func logToFile(msg string) {
	// 创建日志文件（追加模式）
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Printf("打开日志文件失败: %v\n", err)
		return
	}
	defer f.Close()

	log.Print(msg)

	// 写入日志
	if _, err := f.WriteString(msg + "\n"); err != nil {
		fmt.Printf("写入日志失败: %v\n", err)
	}
}

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
		MaxAuthTries:                3,
		PublicKeyCallback: func(conn ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			// 检查黑名单
			clientIP := getClientIP(conn.RemoteAddr().String())
			if _, exists := ipBlacklist.Load(clientIP); exists {
				logToFile("拒绝密钥认证，IP已被拉黑" + clientIP)
				return nil, fmt.Errorf("IP已被拉黑")
			}

			if authorizedKeys[string(pubKey.Marshal())] {
				log.Printf("公钥认证成功: %s", conn.RemoteAddr())
				ipFailMap.Delete(clientIP)
				return &ssh.Permissions{}, nil
			}

			isBlack := recordIPFail(clientIP)
			logMsg := fmt.Sprintf("未授权的公钥尝试登录: %s (IP: %s)", conn.RemoteAddr(), clientIP)
			if isBlack {
				logMsg += " | IP已加入黑名单"
				logToFile(fmt.Sprintf("[%s] %s", time.Now().Format(time.RFC3339), logMsg))
			}

			return nil, fmt.Errorf("未授权的公钥")
		},
		PasswordCallback: func(_ ssh.ConnMetadata, _ []byte) (*ssh.Permissions, error) {
			// 检查黑名单
			clientIP := getClientIP(conn.RemoteAddr().String())
			if _, exists := ipBlacklist.Load(clientIP); exists {
				logToFile("拒绝密码认证，IP已被拉黑" + clientIP)
				return nil, fmt.Errorf("IP已被拉黑")
			}

			isBlack := recordIPFail(clientIP)
			logMsg := fmt.Sprintf("禁止使用密码登录: %s (IP: %s)", conn.RemoteAddr(), clientIP)
			if isBlack {
				logMsg += " | IP已加入黑名单"
				logToFile(fmt.Sprintf("[%s] %s", time.Now().Format(time.RFC3339), logMsg))
			}

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

	appDir := getAppDir()

	// 启动时加载黑名单
	blacklistFile = filepath.Join(appDir, blacklistDirName, blacklistFileName)
	logFile = filepath.Join(appDir, logFileName)
	loadBlacklist()

	// 核心逻辑2：未指定 -client_key，启动SFTP服务器
	// 1. 初始化路径（核心区分：密钥存当前目录，操作目录是FILES）                    // 程序运行目录
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
