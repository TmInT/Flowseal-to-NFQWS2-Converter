// Package strattest проверяет стратегии обхода на живом трафике: как test zapret.ps1
// из Flowseal, только nfqws2 работает на роутере, а запросы идут с этого ПК.
package strattest

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Статусы проверки.
const (
	StatusOK      = "OK"
	StatusError   = "ERROR" // таймаут, обрыв, недоступность
	StatusSSL     = "SSL"   // подмена или ошибка сертификата
	StatusBlocked = "BLOCKED"
)

// Режимы TLS-проверки: обычная (как --http1.1 в curl), только 1.2, только 1.3.
const (
	ModeDefault = "default"
	ModeTLS12   = "tls12"
	ModeTLS13   = "tls13"
)

var Modes = []string{ModeDefault, ModeTLS12, ModeTLS13}

var ModeLabel = map[string]string{ModeDefault: "HTTP", ModeTLS12: "TLS1.2", ModeTLS13: "TLS1.3"}

// DPIPayload — размер POST-запроса для проверки «TCP 16-20 freeze».
const DPIPayload = 65536

const userAgent = "curl/8.4.0 F2N"

// testRoots — доверенные сертификаты тестов (в реальной работе nil: используется
// системное хранилище).
var testRoots *x509.CertPool

// newClient каждый раз создаёт новый транспорт: нужна свежая TCP/TLS-связь,
// именно на ней срабатывает DPI. Проки игнорируются — проверяем прямой путь.
func newClient(mode string, timeout time.Duration) (*http.Client, func()) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: testRoots}
	switch mode {
	case ModeTLS12:
		cfg.MaxVersion = tls.VersionTLS12
	case ModeTLS13:
		cfg.MinVersion = tls.VersionTLS13
	}
	tr := &http.Transport{
		TLSClientConfig:       cfg,
		Proxy:                 nil,
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     false,
		MaxConnsPerHost:       1,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		DialContext:           (&net.Dialer{Timeout: timeout}).DialContext,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
		// любой ответ сервера — успех: важно, что он дошёл
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return client, tr.CloseIdleConnections
}

// isCertError — ошибка проверки сертификата (DPI подсунул свой или перехватил).
func isCertError(err error) bool {
	var cv *tls.CertificateVerificationError
	var ua x509.UnknownAuthorityError
	var he x509.HostnameError
	var ci x509.CertificateInvalidError
	return errors.As(err, &cv) || errors.As(err, &ua) || errors.As(err, &he) || errors.As(err, &ci)
}

// CheckURL выполняет HEAD-запрос и классифицирует результат.
// Пустая строка — проверку отменили, результат не учитывается.
func CheckURL(ctx context.Context, rawURL, mode string, timeout time.Duration) string {
	client, done := newClient(mode, timeout)
	defer done()
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, rawURL, nil)
	if err != nil {
		return StatusError
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
		return StatusOK
	}
	if ctx.Err() != nil {
		return ""
	}
	if isCertError(err) {
		return StatusSSL
	}
	return StatusError
}

// CheckDPI — POST 64 КБ на host с таймаутом. Запрос ушёл целиком, а ответа нет —
// так выглядит заморозка на 16-20 КБ (как в dpi-checkers hyperion-cs).
func CheckDPI(ctx context.Context, host, mode string, timeout time.Duration) string {
	client, done := newClient(mode, timeout)
	defer done()
	body := make([]byte, DPIPayload)
	_, _ = rand.Read(body)
	var wrote atomic.Bool
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			if info.Err == nil {
				wrote.Store(true)
			}
		},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+host, bytes.NewReader(body))
	if err != nil {
		return StatusError
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Range", "bytes=0-"+strconv.Itoa(DPIPayload-1))
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := client.Do(req)
	if err == nil {
		_, _ = io.CopyN(io.Discard, resp.Body, 4096)
		resp.Body.Close()
		return StatusOK
	}
	if ctx.Err() != nil {
		return ""
	}
	var ne net.Error
	if wrote.Load() && (errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout())) {
		return StatusBlocked
	}
	return StatusError
}

// parallel вызывает fn(i) для i из [0;count) не более чем n воркеров.
func parallel(ctx context.Context, n, count int, fn func(i int)) {
	if n < 1 {
		n = 1
	}
	sem := make(chan struct{}, n)
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			fn(i)
		}(i)
	}
	wg.Wait()
}
