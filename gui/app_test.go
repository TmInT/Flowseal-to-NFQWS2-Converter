package main

import (
	"strings"
	"testing"
)

// TestPreviewResolvesBatFilename — GUI передаёт имя файла из списка,
// конвертер должен сам склеивать его с папкой Flowseal.
func TestPreviewResolvesBatFilename(t *testing.T) {
	a := NewApp()
	res, err := a.Preview(ConvertOpts{
		Dir:   `G:\zapret-discord-youtube-1.10.4`,
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
