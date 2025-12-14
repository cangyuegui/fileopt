package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"

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

func generateHostKey(path string) error {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	f, _ := os.Create(path)
	defer f.Close()
	return pem.Encode(f, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

func main() {
	addr := flag.String("addr", ":2022", "listen address")
	flag.Parse()

	exe, _ := os.Executable()
	root := filepath.Join(filepath.Dir(exe), "FILES")
	os.MkdirAll(root, 0755)

	keyPath := "host.key"
	if _, err := os.Stat(keyPath); err != nil {
		generateHostKey(keyPath)
	}

	keyBytes, _ := os.ReadFile(keyPath)
	hostKey, _ := ssh.ParsePrivateKey(keyBytes)

	cfg := &ssh.ServerConfig{
		NoClientAuth: true,
	}
	cfg.AddHostKey(hostKey)

	ln, _ := net.Listen("tcp", *addr)
	log.Println("SFTP listening on", *addr)
	log.Println("Root:", root)

	for {
		c, _ := ln.Accept()
		go func() {
			defer c.Close()

			sshConn, chans, reqs, err := ssh.NewServerConn(c, cfg)
			if err != nil {
				return
			}
			defer sshConn.Close()
			go ssh.DiscardRequests(reqs)

			for ch := range chans {
				if ch.ChannelType() != "session" {
					ch.Reject(ssh.UnknownChannelType, "")
					continue
				}
				channel, requests, _ := ch.Accept()

				go func() {
					for r := range requests {
						if r.Type == "subsystem" &&
							string(r.Payload[4:]) == "sftp" {
							r.Reply(true, nil)

							server := sftp.NewRequestServer(
								channel,
								sftp.Handlers{
									FileGet:  NewSecureHandler(root),
									FilePut:  NewSecureHandler(root),
									FileCmd:  NewSecureHandler(root),
									FileList: NewSecureHandler(root),
								},
							)
							server.Serve()
							return
						}
						r.Reply(false, nil)
					}
				}()
			}
		}()
	}
}
