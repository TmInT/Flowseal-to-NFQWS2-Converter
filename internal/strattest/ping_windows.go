//go:build windows

package strattest

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

// PingResult — итог ping одной цели (MS в миллисекундах).
type PingResult struct {
	OK bool
	MS int
}

// PingBatch пингует все цели за один запуск PowerShell с .NET Ping — так же, как
// test zapret.ps1 у Flowseal. Запасной вариант — нативный IcmpSendEcho: он даёт
// верный факт ответа, но на некоторых системах завышает время отклика (замерено
// +220 мс к шлюзу), поэтому остаётся только на случай проблем с PowerShell.
func PingBatch(ctx context.Context, hosts []string, timeout time.Duration) map[string]PingResult {
	if len(hosts) == 0 {
		return nil
	}
	if res, err := pingDotNet(ctx, hosts, timeout); err == nil {
		return res
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	res := make(map[string]PingResult, len(hosts))
	for _, h := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			ok, d := pingNative(ctx, h, timeout)
			mu.Lock()
			res[h] = PingResult{OK: ok, MS: int(d / time.Millisecond)}
			mu.Unlock()
		}(h)
	}
	wg.Wait()
	return res
}

var rePingLine = regexp.MustCompile(`^(.+)\|([01])\|(\d+)$`)

// pingDotNet: "$p = New-Object System.Net.NetworkInformation.Ping" на каждую цель,
// результат — строками "host|1|мс" / "host|0|0". Скрипт уходит в -EncodedCommand,
// чтобы не зависеть от кавычек и кодировки командной строки.
func pingDotNet(ctx context.Context, hosts []string, timeout time.Duration) (map[string]PingResult, error) {
	ms := int(timeout / time.Millisecond)
	if ms < 1 {
		ms = 1000
	}
	var b strings.Builder
	b.WriteString("$ErrorActionPreference='SilentlyContinue';")
	for _, h := range hosts {
		if h == "" || strings.ContainsAny(h, "'\"`\\ \t\r\n|;(){}$") {
			continue // адреса целей — только IP и домены
		}
		fmt.Fprintf(&b, "try{$p=New-Object System.Net.NetworkInformation.Ping;$r=$p.Send('%s',%d);$p.Dispose();if($r.Status -eq 'Success'){'%s|1|'+$r.RoundtripTime}else{'%s|0|0'}}catch{'%s|0|0'};", h, ms, h, h, h)
	}
	enc := base64.StdEncoding.EncodeToString(utf16LE(b.String()))
	cctx, cancel := context.WithTimeout(ctx, time.Duration(len(hosts)+4)*timeout)
	defer cancel()
	out, err := exec.CommandContext(cctx, "powershell.exe", "-NoProfile", "-NonInteractive",
		"-ExecutionPolicy", "Bypass", "-EncodedCommand", enc).Output()
	if err != nil {
		return nil, err
	}
	res := make(map[string]PingResult, len(hosts))
	for _, ln := range strings.Split(strings.ReplaceAll(string(out), "\r", ""), "\n") {
		m := rePingLine.FindStringSubmatch(strings.TrimSpace(ln))
		if m == nil {
			continue
		}
		ok, ms := m[2] == "1", 0
		fmt.Sscan(m[3], &ms)
		res[m[1]] = PingResult{OK: ok, MS: ms}
	}
	if len(res) == 0 {
		return nil, fmt.Errorf("PowerShell не вернул ни одного результата")
	}
	return res, nil
}

func utf16LE(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, v := range u {
		binary.LittleEndian.PutUint16(b[i*2:], v)
	}
	return b
}

var (
	iphlpapi            = syscall.NewLazyDLL("iphlpapi.dll")
	procIcmpCreateFile  = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpSendEcho    = iphlpapi.NewProc("IcmpSendEcho")
	procIcmpCloseHandle = iphlpapi.NewProc("IcmpCloseHandle")
)

// pingNative — запасной вариант: IcmpSendEcho без прав администратора.
// RequestOptions должен быть NULL: с непустой структурой Windows возвращает IP_BUF_TOO_SMALL.
func pingNative(ctx context.Context, host string, timeout time.Duration) (bool, time.Duration) {
	ip := net.ParseIP(host)
	if ip == nil {
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
		if err != nil || len(ips) == 0 {
			return false, 0
		}
		ip = ips[0]
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false, 0
	}
	h, _, _ := procIcmpCreateFile.Call()
	if h == 0 || h == uintptr(syscall.InvalidHandle) {
		return false, 0
	}
	defer procIcmpCloseHandle.Call(h)
	data := []byte("f2n-strattest")
	var reply [256]byte
	ms := uintptr(timeout / time.Millisecond)
	if ms == 0 {
		ms = 1000
	}
	ret, _, _ := procIcmpSendEcho.Call(h, uintptr(binary.BigEndian.Uint32(ip4)),
		uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)),
		0, uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), ms)
	if ret == 0 {
		return false, 0
	}
	// ICMP_ECHO_REPLY: Address, Status, RoundTripTime
	if binary.LittleEndian.Uint32(reply[4:8]) != 0 {
		return false, 0
	}
	return true, time.Duration(binary.LittleEndian.Uint32(reply[8:12])) * time.Millisecond
}
