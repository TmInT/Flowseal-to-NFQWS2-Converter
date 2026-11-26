// SSH-реализация strattest.Router: что тестер стратегий делает с роутером.
package main

import (
	"fmt"
	"strings"
	"time"

	"f2n/internal/sshctl"
	"f2n/internal/strattest"
)

type sshRouter struct{ c *sshctl.Client }

func (r sshRouter) Conf() (string, error) {
	return r.c.ReadFile(sshctl.ConfPath)
}

func (r sshRouter) Backup() (string, error) {
	bak := sshctl.ConfPath + ".bak-f2n-test-" + time.Now().Format("20060102-150405")
	if _, err := r.c.Run("cp " + sshctl.ConfPath + " " + bak); err != nil {
		return "", fmt.Errorf("бэкап: %w", err)
	}
	return bak, nil
}

func (r sshRouter) WriteConf(conf string) error {
	if err := r.c.WriteFile(sshctl.ConfPath, conf); err != nil {
		return fmt.Errorf("запись конфига: %w", err)
	}
	got, err := r.c.ReadFile(sshctl.ConfPath)
	if err != nil || strings.TrimRight(got, "\r\n") != strings.TrimRight(conf, "\r\n") {
		return fmt.Errorf("проверка записи: конфиг на роутере отличается")
	}
	return nil
}

func (r sshRouter) Restart() error { return r.service("restart", true) }
func (r sshRouter) Stop() error    { return r.service("stop", false) }
func (r sshRouter) Start() error   { return r.service("start", true) }

// service: «S51nfqws2 status» всегда возвращает 0, поэтому состояние
// определяется по ответу, а не по коду завершения.
func (r sshRouter) service(action string, mustRun bool) error {
	out, err := r.c.Service(action)
	running, _ := r.running()
	if mustRun && !running {
		if err != nil {
			return fmt.Errorf("%w", err)
		}
		return fmt.Errorf("служба не поднялась (%s)", firstLine(out))
	}
	return nil
}

func (r sshRouter) running() (bool, error) {
	out, err := r.c.Service("status")
	if err != nil {
		return false, err
	}
	return strings.Contains(strings.ToLower(out), "is running"), nil
}

func (r sshRouter) ReadFile(path string) (string, error) { return r.c.ReadFile(path) }
func (r sshRouter) WriteFile(path, content string) error {
	return r.c.WriteFile(path, content)
}

// интерфейс собран полностью
var _ strattest.Router = sshRouter{}
