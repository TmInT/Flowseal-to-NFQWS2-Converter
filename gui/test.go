// Тест стратегий: методы для фронтенда (window.go.main.App.Test*).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"f2n/internal/convert"
	"f2n/internal/sshctl"
	"f2n/internal/strattest"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// TestRequest — параметры теста стратегий.
type TestRequest struct {
	Dir        string   `json:"dir"`
	Iface      string   `json:"iface"`
	Policy     string   `json:"policy"`
	GF         string   `json:"gf"`
	Strategies []string `json:"strategies"`
	Baseline   bool     `json:"baseline"`
	DPI        bool     `json:"dpi"`
	Rounds     int      `json:"rounds"`
}

var testCancel chan struct{}

// journalPath — отметка о незавершённом тесте: по ней следующая сессия
// предлагает вернуть роутер в исходное состояние.
func journalPath() string { return filepath.Join(exeDir(), "strattest-pending.json") }

// TestPending возвращает незавершённый тест или nil.
func (a *App) TestPending() (*strattest.Journal, error) {
	data, err := os.ReadFile(journalPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var j strattest.Journal
	if err := json.Unmarshal(data, &j); err != nil {
		return nil, fmt.Errorf("файл незавершённого теста повреждён: %w", err)
	}
	return &j, nil
}

func clearJournal() { _ = os.Remove(journalPath()) }

// TestStrategies по очереди ставит стратегии на роутер и проверяет их с этого ПК.
// Прогресс идёт событием "test:progress"; прежний конфиг возвращается всегда.
func (a *App) TestStrategies(r Router, req TestRequest) (*strattest.Report, error) {
	cancel := make(chan struct{})
	testCancel = cancel
	onJournal := func(j *strattest.Journal) {
		if j == nil {
			clearJournal()
			return
		}
		// копия конфига и списков на ПК — на случай, если бэкап на роутере пропадёт
		dir := filepath.Join(exeDir(), "backups", time.Now().Format("20060102-150405")+"-strattest")
		_ = os.MkdirAll(dir, 0o755)
		_ = os.WriteFile(filepath.Join(dir, "nfqws2.conf"), []byte(j.Conf), 0o644)
		for p, c := range j.Lists {
			_ = os.WriteFile(filepath.Join(dir, filepath.Base(p)), []byte(c), 0o644)
		}
		if data, err := json.MarshalIndent(j, "", "  "); err == nil {
			_ = os.WriteFile(journalPath(), data, 0o644)
		}
	}
	opts := strattest.Options{
		Convert: convert.Options{
			FlowsealDir: req.Dir, Interface: req.Iface, Policy: req.Policy, GameFilter: strings.ToLower(req.GF),
		},
		Strategies: req.Strategies,
		Baseline:   req.Baseline,
		DPI:        req.DPI,
		Rounds:     req.Rounds,
		Cancel:     cancel,
		OnJournal:  onJournal,
	}
	if a.ctx != nil {
		opts.Progress = func(p strattest.Progress) {
			runtime.EventsEmit(a.ctx, "test:progress", map[string]interface{}{
				"step": p.Step, "total": p.Total, "msg": p.Msg,
			})
		}
	}
	defer func() { testCancel = nil }()
	return strattest.Run(context.Background(), sshRouter{a.sshClient(r)}, opts), nil
}

// CancelTest останавливает тест после текущей стратегии.
func (a *App) CancelTest() {
	if testCancel != nil {
		close(testCancel)
		testCancel = nil
	}
}

// TestRestore возвращает конфиг и списки на место после прерванного теста.
func (a *App) TestRestore(r Router) (string, error) {
	j, err := a.TestPending()
	if err != nil {
		return "", err
	}
	if j == nil {
		return "", fmt.Errorf("незавершённых тестов нет")
	}
	c := a.sshClient(r)
	rt := sshRouter{c}
	// конфиг — из бэкапа на роутере; локальная копия — запасной вариант
	if _, err := c.Run("cp " + j.Backup + " " + sshctl.ConfPath); err != nil {
		if j.Conf == "" {
			return "", fmt.Errorf("бэкап %s на роутере недоступен", j.Backup)
		}
		if err := rt.WriteConf(j.Conf); err != nil {
			return "", fmt.Errorf("восстановление конфига: %w", err)
		}
	}
	for p, content := range j.Lists {
		if err := rt.WriteFile(p, content); err != nil {
			return "", fmt.Errorf("восстановление %s: %w", filepath.Base(p), err)
		}
	}
	if err := rt.Restart(); err != nil {
		return "", fmt.Errorf("конфиг возвращён, но служба не поднялась: %w", err)
	}
	clearJournal()
	return "Роутер восстановлен из " + j.Backup, nil
}

// SaveTextFile предлагает сохранить текстовый отчёт.
func (a *App) SaveTextFile(defaultName, text string) (string, error) {
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:                "Сохранить отчёт",
		DefaultFilename:      defaultName,
		CanCreateDirectories: true,
		Filters:              []runtime.FileFilter{{DisplayName: "Текст", Pattern: "*.txt"}},
	})
	if err != nil || path == "" {
		return "", err
	}
	return path, os.WriteFile(path, []byte(text), 0o644)
}
