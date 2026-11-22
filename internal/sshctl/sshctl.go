// Package sshctl управляет nfqws2 на роутере по SSH (Entware/dropbear):
// /opt/etc/init.d/S51nfqws2 {start|stop|restart|reload|status}, чтение/запись файлов.
package sshctl

import (
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	ScriptPath = "/opt/etc/init.d/S51nfqws2"
	ConfPath   = "/opt/etc/nfqws2/nfqws2.conf"
	ListsDir   = "/opt/etc/nfqws2/lists"
	LogPath    = "/opt/var/log/nfqws2.log"
)

type Options struct {
	Host    string // 192.168.1.1
	Port    int    // 22
	User    string // root
	Pass    string
	Timeout time.Duration
}

type Client struct {
	opts Options
}

func New(opts Options) *Client {
	if opts.Port == 0 {
		opts.Port = 22
	}
	if opts.Timeout == 0 {
		opts.Timeout = 15 * time.Second
	}
	return &Client{opts: opts}
}

func (c *Client) dial() (*ssh.Client, error) {
	cfg := &ssh.ClientConfig{
		User: c.opts.User,
		Auth: []ssh.AuthMethod{ssh.Password(c.opts.Pass)},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil // домашняя сеть: ключи dropbear не проверяем
		},
		Timeout: c.opts.Timeout,
	}
	addr := fmt.Sprintf("%s:%d", c.opts.Host, c.opts.Port)
	return ssh.Dial("tcp", addr, cfg)
}

// Run выполняет команду и возвращает объединённый stdout+stderr.
func (c *Client) Run(cmd string) (string, error) {
	scl, err := c.dial()
	if err != nil {
		return "", fmt.Errorf("SSH-подключение к %s:%d: %w", c.opts.Host, c.opts.Port, err)
	}
	defer scl.Close()
	sess, err := scl.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	var out strings.Builder
	sess.Stdout = &out
	sess.Stderr = &out
	if err := sess.Run(cmd); err != nil {
		return strings.TrimSpace(out.String()), fmt.Errorf("%w (вывод: %s)", err, strings.TrimSpace(out.String()))
	}
	return strings.TrimSpace(out.String()), nil
}

// writeFile пишет файл на роутер через stdin (без sftp).
func (c *Client) WriteFile(path, content string) error {
	scl, err := c.dial()
	if err != nil {
		return err
	}
	defer scl.Close()
	sess, err := scl.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	stdin, err := sess.StdinPipe()
	if err != nil {
		return err
	}
	if err := sess.Start("cat > " + path); err != nil {
		return err
	}
	if _, err := stdin.Write([]byte(content)); err != nil {
		return err
	}
	if err := stdin.Close(); err != nil {
		return err
	}
	return sess.Wait()
}

func (c *Client) ReadFile(path string) (string, error) {
	out, err := c.Run("cat " + path + " 2>/dev/null")
	if err != nil {
		return "", err
	}
	return out, nil
}

// Service выполняет действие скрипта управления: start|stop|restart|reload|status.
func (c *Client) Service(action string) (string, error) {
	switch action {
	case "start", "stop", "restart", "reload", "status":
	default:
		return "", fmt.Errorf("недопустимое действие: %s", action)
	}
	return c.Run(ScriptPath + " " + action)
}

// Status возвращает статус службы + наличие правил nfqws в iptables.
func (c *Client) Status() (string, error) {
	st, err := c.Service("status")
	if err != nil {
		return st, nil // status скрипта может возвращать ненулевой код — это норма
	}
	ipt, _ := c.Run("iptables-save 2>/dev/null | grep -c nfqws")
	return st + "\nПравил nfqws в iptables: " + ipt, nil
}

// LogTail возвращает последние n строк лога автохостлиста.
func (c *Client) LogTail(n int) (string, error) {
	return c.Run(fmt.Sprintf("tail -n %d %s 2>/dev/null || echo '(лог пуст)'", n, LogPath))
}

// ConfReader возвращает функцию чтения списков роутера.
func (c *Client) ListReader() func(name string) (string, error) {
	return func(name string) (string, error) {
		return c.ReadFile(ListsDir + "/" + name)
	}
}

// DeployStep выполняет одну команду деплоя с проверкой.
func (c *Client) DeployStep(desc, cmd string) (string, error) {
	out, err := c.Run(cmd)
	if err != nil {
		return out, fmt.Errorf("%s: %w", desc, err)
	}
	return out, nil
}

// WriteConf записывает конфиг с предварительным бэкапом. Возвращает имя бэкапа.
func (c *Client) WriteConf(conf string) (string, error) {
	stamp := time.Now().Format("20060102-150405")
	bak := ConfPath + ".bak-f2n-" + stamp
	if _, err := c.Run("cp " + ConfPath + " " + bak); err != nil {
		return "", fmt.Errorf("бэкап: %w", err)
	}
	if err := c.WriteFile(ConfPath, conf); err != nil {
		return "", fmt.Errorf("запись конфига: %w", err)
	}
	// верификация
	got, err := c.ReadFile(ConfPath)
	if err != nil {
		return bak, fmt.Errorf("проверка конфига: %w", err)
	}
	if got != strings.TrimRight(conf, "\n") {
		return bak, fmt.Errorf("проверка конфига: содержимое на роутере отличается")
	}
	return bak, nil
}

// MergeList читает список, добавляет недостающие строки и записывает обратно.
func (c *Client) MergeList(name string, additions []string) (int, error) {
	cur, err := c.ReadFile(ListsDir + "/" + name)
	if err != nil {
		cur = "" // списка может не быть
	}
	seen := map[string]bool{}
	var out []string
	for _, ln := range strings.Split(cur, "\n") {
		ln = strings.TrimRight(ln, "\r")
		out = append(out, ln)
		t := strings.ToLower(strings.TrimSpace(ln))
		if t != "" {
			seen[t] = true
		}
	}
	added := 0
	for _, a := range additions {
		a = strings.TrimRight(a, "\r")
		t := strings.ToLower(strings.TrimSpace(a))
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, a)
		added++
	}
	if added == 0 {
		return 0, nil
	}
	if err := c.WriteFile(ListsDir+"/"+name, strings.Join(out, "\n")+"\n"); err != nil {
		return 0, fmt.Errorf("запись %s: %w", name, err)
	}
	return added, nil
}

