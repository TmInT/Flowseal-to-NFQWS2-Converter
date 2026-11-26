package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPreviewResolvesBatFilename — GUI передаёт имя файла из списка,
// конвертер должен сам склеивать его с папкой Flowseal.
func TestPreviewResolvesBatFilename(t *testing.T) {
	a := NewApp()
	res, err := a.Preview(ConvertOpts{
		Dir:   `../testdata/flowseal`,
		Bat:   "general (ALT11).bat", // только имя, как в GUI-списке
		Iface: "eth3",
		GF:    "all",
	})
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if !strings.Contains(res.Conf, "NFQWS_ARGS_QUIC") {
		t.Fatalf("конфиг без NFQWS_ARGS_QUIC")
	}
	if !strings.Contains(res.Conf, "active_discord_udp") {
		t.Fatalf("конфиг без активного discord-фейка")
	}
}

// TestListBatsSkipsService — service*.bat в списке стратегий показываться
// не должен: это менеджер службы, а не стратегия обхода.
func TestListBatsSkipsService(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"service.bat", "general.bat", "general (ALT11).bat", "SERVICE.BAT"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("@echo off\r\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := NewApp().ListBats(dir)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, "|") != "general (ALT11).bat|general.bat" {
		t.Errorf("ListBats = %v", got)
	}
}
