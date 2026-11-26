//go:build windows

package strattest

import (
	"os/exec"
	"strings"
	"syscall"
)

// Diagnostics — настройки этого ПК, которые искажают результаты теста
// (те же проверки, что делает service.bat у Flowseal).
func Diagnostics() []string {
	var out []string
	if proxyEnabled() {
		out = append(out, "На ПК включён системный прокси — браузеры могут ходить через него мимо роутера, результаты теста относятся только к прямым запросам")
	}
	if on, known := tcpTimestamps(); known && !on {
		out = append(out, "На ПК выключены TCP-таймстампы: стратегии с fooling=ts не смогут отбрасывать фейки. Flowseal включает их командой «netsh interface tcp set global timestamps=enabled» (нужны права администратора)")
	}
	return out
}

func proxyEnabled() bool {
	var key syscall.Handle
	err := syscall.RegOpenKeyEx(syscall.HKEY_CURRENT_USER,
		syscall.StringToUTF16Ptr(`Software\Microsoft\Windows\CurrentVersion\Internet Settings`), 0, syscall.KEY_READ, &key)
	if err != nil {
		return false
	}
	defer syscall.RegCloseKey(key)
	var buf [4]byte
	n := uint32(len(buf))
	if syscall.RegQueryValueEx(key, syscall.StringToUTF16Ptr("ProxyEnable"), nil, nil, &buf[0], &n) != nil {
		return false
	}
	return buf[0] != 0
}

// tcpTimestamps: (включены, удалось ли определить).
func tcpTimestamps() (bool, bool) {
	out, err := exec.Command("netsh", "interface", "tcp", "show", "global").Output()
	if err != nil {
		return false, false
	}
	for _, ln := range strings.Split(strings.ToLower(string(out)), "\n") {
		if !strings.Contains(ln, "timestamp") && !strings.Contains(ln, "метк") {
			continue
		}
		switch {
		case strings.Contains(ln, "enabled"), strings.Contains(ln, "включен"), strings.Contains(ln, "включён"):
			return true, true
		case strings.Contains(ln, "disabled"), strings.Contains(ln, "выключен"):
			return false, true
		}
	}
	return false, false
}
