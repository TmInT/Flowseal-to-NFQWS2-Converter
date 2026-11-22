// GUI-приложение f2n: обёртка над конвертером и SSH-управлением nfqws2.
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"f2n/internal/convert"
	"f2n/internal/sshctl"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// App — публичные методы привязываются к фронтенду (window.go.main.App.*).
type App struct {
	ctx context.Context
}

func NewApp() *App { return &App{} }

func (a *App) startup(ctx context.Context) { a.ctx = ctx }

// ConvertResult — результат конвертации для фронтенда.
type ConvertResult struct {
	Conf      string   `json:"conf"`
	SlotTable []string `json:"slotTable"`
	Warnings  []string `json:"warnings"`
	Infos     []string `json:"infos"`
}

type ConvertOpts struct {
	Dir     string `json:"dir"`
	Bat     string `json:"bat"`
	Iface   string `json:"iface"`
	Policy  string `json:"policy"`
	GF      string `json:"gf"`
	Strict  bool   `json:"strict"`
}

func (a *App) toOpts(o ConvertOpts, outDir string) convert.Options {
	bat := o.Bat
	if bat != "" {
		if _, err := os.Stat(bat); err != nil {
			// из списка стратегий приходит имя файла — склеиваем с папкой
			bat = filepath.Join(o.Dir, bat)
		}
	}
	return convert.Options{
		FlowsealDir: o.Dir,
		BatFile:     bat,
		OutputDir:   outDir,
		Interface:   o.Iface,
		Policy:      o.Policy,
		GameFilter:  strings.ToLower(o.GF),
		Strict:      o.Strict,
	}
}

// ListBats возвращает список .bat-профилей в папке Flowseal.
func (a *App) ListBats(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".bat") {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

// PickFolder открывает системный диалог выбора папки.
func (a *App) PickFolder() (string, error) {
	return runtime.OpenDirectoryDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Выберите папку zapret-discord-youtube",
	})
}

// Preview конвертирует и возвращает результат без записи на диск.
func (a *App) Preview(o ConvertOpts) (*ConvertResult, error) {
	res, err := convert.Run(a.toOpts(o, "converted"))
	if err != nil {
		return nil, err
	}
	return &ConvertResult{
		Conf:      res.Conf,
		SlotTable: res.SlotTable,
		Warnings:  res.Warnings,
		Infos:     res.Infos,
	}, nil
}

// ExportResult — файлы и каталог экспорта.
type ExportResult struct {
	Files  []string `json:"files"`
	OutDir string   `json:"outDir"`
}

// ExportLocal сохраняет результат конвертации локально (ручная установка).
func (a *App) ExportLocal(o ConvertOpts) (*ExportResult, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	outDir := filepath.Join(filepath.Dir(exe), "converted")
	res, err := convert.Run(a.toOpts(o, outDir))
	if err != nil {
		return nil, err
	}
	files, err := convert.WriteOutputs(a.toOpts(o, outDir), res)
	if err != nil {
		return nil, err
	}
	return &ExportResult{Files: files, OutDir: outDir}, nil
}

// Router — параметры SSH-подключения к роутеру.
type Router struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	User string `json:"user"`
	Pass string `json:"pass"`
}

func (a *App) sshClient(r Router) *sshctl.Client {
	port := r.Port
	if port == 0 {
		port = 222
	}
	return sshctl.New(sshctl.Options{Host: r.Host, Port: port, User: r.User, Pass: r.Pass})
}

// RouterCheck проверяет SSH-доступ и наличие конфига nfqws2.
func (a *App) RouterCheck(r Router) (string, error) {
	c := a.sshClient(r)
	out, err := c.Run("test -f /opt/etc/nfqws2/nfqws2.conf && echo 'SSH OK, конфиг на месте' && /opt/etc/init.d/S51nfqws2 status")
	if err != nil {
		return out, err
	}
	return out, nil
}

// exeDir возвращает каталог, где лежит .exe (туда же пишутся бэкапы и артефакты).
func exeDir() string {
	exe, err := os.Executable()
	if err != nil {
		d, _ := os.Getwd()
		return d
	}
	return filepath.Dir(exe)
}

// DeploySSH конвертирует и устанавливает: бэкап → конфиг → списки → restart → status.
func (a *App) DeploySSH(o ConvertOpts, r Router, updateLists bool) ([]string, error) {
	outDir := filepath.Join(exeDir(), "last-deploy")
	res, err := convert.Run(a.toOpts(o, outDir))
	if err != nil {
		return nil, err
	}
	if _, err := convert.WriteOutputs(a.toOpts(o, outDir), res); err != nil {
		return nil, err
	}
	c := a.sshClient(r)
	adds, _ := convert.ListAdditions(o.Dir)
	return a.deployKit(c, res.Conf, adds, updateLists)
}

// DeployFromFolder устанавливает на роутер ранее сохранённую конвертацию
// (папка с nfqws2.conf и, при наличии, lists/*.add) — без повторной конвертации.
func (a *App) DeployFromFolder(r Router, folder string, updateLists bool) ([]string, error) {
	confPath := filepath.Join(folder, "nfqws2.conf")
	conf, err := os.ReadFile(confPath)
	if err != nil {
		return nil, fmt.Errorf("в папке нет nfqws2.conf: %w", err)
	}
	adds := map[string][]string{}
	if entries, err := os.ReadDir(filepath.Join(folder, "lists")); err == nil {
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".add") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(folder, "lists", e.Name()))
			if err != nil {
				continue
			}
			var lines []string
			for _, ln := range strings.Split(string(data), "\n") {
				ln = strings.TrimSpace(ln)
				if ln != "" {
					lines = append(lines, ln)
				}
			}
			adds[strings.TrimSuffix(e.Name(), ".add")] = lines
		}
	}
	c := a.sshClient(r)
	return a.deployKit(c, string(conf), adds, updateLists)
}

// deployKit: бэкап → конфиг → списки (дополнение с бэкапами) → restart → статус.
func (a *App) deployKit(c *sshctl.Client, conf string, adds map[string][]string, updateLists bool) ([]string, error) {
	logs := []string{}
	logf := func(s string) { logs = append(logs, s) }

	stamp := time.Now().Format("20060102-150405")
	bak := "/opt/etc/nfqws2/nfqws2.conf.bak-f2n-" + stamp
	curConf, rerr := c.ReadFile("/opt/etc/nfqws2/nfqws2.conf")
	if _, err := c.Run("cp /opt/etc/nfqws2/nfqws2.conf " + bak); err != nil {
		return nil, fmt.Errorf("бэкап: %w", err)
	}
	bakDir := filepath.Join(exeDir(), "backups", stamp)
	_ = os.MkdirAll(bakDir, 0o755)
	if rerr == nil {
		_ = os.WriteFile(filepath.Join(bakDir, "nfqws2.conf"), []byte(curConf), 0o644)
	}
	logf("Бэкап конфига: " + bak + " (на роутере) и backups\\" + stamp + "\\nfqws2.conf (на ПК)")

	if err := c.WriteFile("/opt/etc/nfqws2/nfqws2.conf", conf); err != nil {
		return nil, fmt.Errorf("запись конфига: %w", err)
	}
	logf("Конфиг записан и проверен чтением")

	if updateLists {
		for _, name := range []string{"user.list", "exclude.list", "ipset.list", "ipset_exclude.list"} {
			orig, _ := c.ReadFile("/opt/etc/nfqws2/lists/" + name)
			_, _ = c.Run("test -f /opt/etc/nfqws2/lists/" + name + " && cp /opt/etc/nfqws2/lists/" + name + " /opt/etc/nfqws2/lists/" + name + ".bak-f2n-" + stamp)
			if orig != "" {
				_ = os.WriteFile(filepath.Join(bakDir, name), []byte(orig), 0o644)
			}
			n, err := c.MergeList(name, adds[name])
			if err != nil {
				return nil, fmt.Errorf("список %s: %w", name, err)
			}
			logf(fmt.Sprintf("Список %s: +%d строк (дополнение, бэкап сделан)", name, n))
		}
	} else {
		logf("Списки не изменялись (выключено)")
	}

	out, err := c.Run("/opt/etc/init.d/S51nfqws2 restart")
	logf("Restart: " + firstLine(out))
	if err != nil {
		logf("ОТКАТ: cp " + bak + " /opt/etc/nfqws2/nfqws2.conf и повторный restart")
		_, _ = c.Run("cp " + bak + " /opt/etc/nfqws2/nfqws2.conf && /opt/etc/init.d/S51nfqws2 restart")
		return logs, fmt.Errorf("restart: %w", err)
	}
	time.Sleep(3 * time.Second)
	st, _ := c.Run("/opt/etc/init.d/S51nfqws2 status")
	ipt, _ := c.Run("iptables-save 2>/dev/null | grep -c nfqws")
	logf("Статус: " + firstLine(st))
	logf("Правил nfqws в iptables: " + firstLine(ipt))
	logf("ГОТОВО — проверьте Discord/YouTube с клиента")
	return logs, nil
}

// ServiceAction: start|stop|restart|reload|status.
func (a *App) ServiceAction(r Router, action string) (string, error) {
	return a.sshClient(r).Service(strings.ToLower(action))
}

// RouterLog — последние n строк лога автохостлиста.
func (a *App) RouterLog(r Router, n int) (string, error) {
	return a.sshClient(r).LogTail(n)
}

// SaveSettings сохраняет настройки интерфейса.
func (a *App) SaveSettings(jsonText string) error {
	dir, err := settingsDir()
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "settings.json"), []byte(jsonText), 0o644)
}

// LoadSettings возвращает сохранённые настройки (или "").
func (a *App) LoadSettings() (string, error) {
	dir, err := settingsDir()
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(filepath.Join(dir, "settings.json"))
	if err != nil {
		return "", nil // нет настроек — не ошибка
	}
	return string(data), nil
}

func settingsDir() (string, error) {
	base := os.Getenv("APPDATA")
	if base == "" {
		base = os.Getenv("HOME")
	}
	d := filepath.Join(base, "f2n")
	if err := os.MkdirAll(d, 0o755); err != nil {
		return "", err
	}
	return d, nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "\n"); i >= 0 {
		s = s[:i]
	}
	return s
}

