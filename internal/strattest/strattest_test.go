package strattest

import (
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"f2n/internal/convert"
)

func TestCheckURL(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden) // любой ответ — успех
	}))
	defer ok.Close()
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer slow.Close()
	selfsigned := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer selfsigned.Close()

	ctx := context.Background()
	if s := CheckURL(ctx, ok.URL, ModeDefault, 2*time.Second); s != StatusOK {
		t.Errorf("доступный сервер: %s, want OK", s)
	}
	if s := CheckURL(ctx, slow.URL, ModeDefault, 300*time.Millisecond); s != StatusError {
		t.Errorf("молчащий сервер: %s, want ERROR", s)
	}
	if s := CheckURL(ctx, selfsigned.URL, ModeTLS12, 2*time.Second); s != StatusSSL {
		t.Errorf("самоподписанный сертификат: %s, want SSL", s)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if s := CheckURL(cctx, slow.URL, ModeDefault, 2*time.Second); s != "" {
		t.Errorf("после отмены: %q, want пусто", s)
	}
}

// Запрос ушёл целиком, ответа нет до таймаута — так выглядит freeze.
func TestCheckDPI(t *testing.T) {
	freeze := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if len(body) != DPIPayload {
			t.Errorf("размер запроса %d, want %d", len(body), DPIPayload)
		}
		if r.Header.Get("Range") == "" {
			t.Errorf("нет заголовка Range")
		}
		time.Sleep(2 * time.Second) // принимает и молчит
	}))
	freeze.StartTLS()
	defer freeze.Close()
	good := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusRequestEntityTooLarge)
	}))
	defer good.Close()

	prev := testRoots
	testRoots = x509.NewCertPool()
	testRoots.AddCert(freeze.Certificate())
	testRoots.AddCert(good.Certificate())
	defer func() { testRoots = prev }()

	ctx := context.Background()
	host := strings.TrimPrefix(freeze.URL, "https://")
	if s := CheckDPI(ctx, host, ModeTLS12, 400*time.Millisecond); s != StatusBlocked {
		t.Errorf("freeze: %s, want BLOCKED", s)
	}
	host = strings.TrimPrefix(good.URL, "https://")
	if s := CheckDPI(ctx, host, ModeTLS12, 2*time.Second); s != StatusOK {
		t.Errorf("отвечающий сервер: %s, want OK", s)
	}
}

// fakeRouter — записывающий дубль роутера.
type fakeRouter struct {
	mu       sync.Mutex
	conf     string
	bak      string
	lists    map[string]string
	running  bool
	events   []string
	failConf error  // ошибка чтения конфига (недоступный SSH)
	failFor  string // подстрока конфига, с которым служба не стартует
}

func (f *fakeRouter) ev(s string) { f.mu.Lock(); f.events = append(f.events, s); f.mu.Unlock() }

func (f *fakeRouter) Conf() (string, error) { return f.conf, f.failConf }
func (f *fakeRouter) Backup() (string, error) {
	f.bak = f.conf
	f.ev("backup")
	return "/opt/etc/nfqws2/nfqws2.conf.bak-f2n-test", nil
}
func (f *fakeRouter) WriteConf(c string) error {
	f.ev("write:" + strings.SplitN(c, "\n", 2)[0])
	f.conf = c
	return nil
}
func (f *fakeRouter) Restart() error {
	f.ev("restart")
	if f.failFor != "" && strings.Contains(f.conf, f.failFor) {
		f.running = false
		return errTest("NFQWS2 daemon exited with an error")
	}
	f.running = true
	return nil
}
func (f *fakeRouter) Stop() error  { f.ev("stop"); f.running = false; return nil }
func (f *fakeRouter) Start() error { f.ev("start"); f.running = true; return nil }
func (f *fakeRouter) ReadFile(p string) (string, error) {
	return f.lists[p], nil
}
func (f *fakeRouter) WriteFile(p, c string) error {
	f.ev("write:" + filepath.Base(p))
	f.lists[p] = c
	return nil
}

type errTest string

func (e errTest) Error() string { return string(e) }

func testOpts(t *testing.T, url string) Options {
	t.Helper()
	return Options{
		Convert:    convert.Options{FlowsealDir: "../../testdata/flowseal", Interface: "eth3", Policy: "nfqws", GameFilter: "all"},
		Strategies: []string{"general.bat", "general (ALT11).bat"},
		Baseline:   true,
		Rounds:     1,
		Timeout:    2 * time.Second,
		Targets: []Target{
			{Name: "Local", URL: url, Host: "127.0.0.1"},
			{Name: "Loop", Host: "127.0.0.1", PingOnly: true},
		},
		Sleep: func(time.Duration) {},
	}
}

// Полный цикл: бэкап → базовый замер → стратегии → конфиг и списки возвращены.
func TestRunRestoresRouter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	r := &fakeRouter{conf: "ORIGINAL CONF", lists: map[string]string{UserList: "discord.com\n", AutoList: "auto.example\n"}, running: true}
	var journal []*Journal
	o := testOpts(t, srv.URL)
	o.Progress = func(p Progress) {
		if p.Step > p.Total {
			t.Errorf("шаг %d больше плана %d", p.Step, p.Total)
		}
	}
	o.OnJournal = func(j *Journal) { journal = append(journal, j) }

	rep := Run(context.Background(), r, o)

	if !rep.Restored || rep.Fatal != "" {
		t.Fatalf("restored=%v fatal=%q warnings=%v", rep.Restored, rep.Fatal, rep.Warnings)
	}
	if r.conf != "ORIGINAL CONF" || !r.running {
		t.Errorf("роутер не возвращён в исходное состояние")
	}
	if r.lists[UserList] != "discord.com\n" || r.lists[AutoList] != "auto.example\n" {
		t.Errorf("списки не восстановлены: %q", r.lists[UserList])
	}
	if len(journal) != 2 || journal[0] == nil || journal[1] != nil {
		t.Fatalf("журнал восстановления: %v", journal)
	}
	if rep.Baseline == nil || len(rep.Results) != 2 {
		t.Fatalf("baseline=%v results=%d", rep.Baseline, len(rep.Results))
	}
	for i, res := range rep.Results {
		if !res.Started || res.Note != "" || res.Score != 100 || res.Rank != i+1 {
			t.Errorf("%s: started=%v note=%q score=%d rank=%d", res.Name, res.Started, res.Note, res.Score, res.Rank)
		}
	}
	if !rep.Results[0].Best || rep.Results[1].Best {
		t.Errorf("лучшая должна быть первая в ранге")
	}
	if got := strings.Join(r.events, " "); !strings.Contains(got, "backup stop start ") {
		t.Errorf("порядок работы: %s", got)
	}
}

// Стратегия, с которой служба не стартует: отметка, служба поднята, тест идёт дальше.
func TestRunKeepsServiceAliveOnBadStrategy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	r := &fakeRouter{conf: "ORIGINAL CONF", lists: map[string]string{}, running: true}
	// "profile: general.bat" — заголовок конфига первой стратегии (вторая его не содержит)
	r.failFor = "Flowseal profile: general.bat"
	o := testOpts(t, srv.URL)
	o.OnJournal = func(*Journal) {}

	rep := Run(context.Background(), r, o)

	if !rep.Restored || r.conf != "ORIGINAL CONF" || !r.running {
		t.Fatalf("restored=%v running=%v", rep.Restored, r.running)
	}
	// результаты выстроены по рангу: рабочая стратегия первая
	good, bad := rep.Results[0], rep.Results[1]
	if !good.Started || good.Rank != 1 || good.Name != "general (ALT11).bat" {
		t.Errorf("рабочая стратегия должна быть первой: %+v", good)
	}
	if bad.Started || !strings.Contains(bad.Note, "не запустился") || bad.Score != 0 || bad.Rank != 2 {
		t.Errorf("плохая стратегия: %+v", bad)
	}
	// с нерабочим конфигом служба сразу поднимается на прежнем
	if got := strings.Join(r.events, " "); !strings.Contains(got, "restart write:ORIGINAL CONF start write:") {
		t.Errorf("после неудачного старта конфиг не возвращён сразу: %s", got)
	}
}

// Отмена до начала: ничего не тестируется, роутер не трогается сверх бэкапа и восстановления.
func TestRunCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	r := &fakeRouter{conf: "ORIGINAL CONF", lists: map[string]string{}, running: true}
	cancel := make(chan struct{})
	close(cancel)
	o := testOpts(t, srv.URL)
	o.Cancel = cancel
	o.OnJournal = func(*Journal) {}

	rep := Run(context.Background(), r, o)

	if !rep.Cancelled || len(rep.Results) != 0 || rep.Baseline != nil {
		t.Errorf("cancelled=%v results=%d baseline=%v", rep.Cancelled, len(rep.Results), rep.Baseline)
	}
	if !rep.Restored || r.conf != "ORIGINAL CONF" {
		t.Errorf("после отмены конфиг не восстановлен")
	}
}

func TestMergeList(t *testing.T) {
	got, n := mergeList("discord.com\r\nYouTube.com\n", []string{"youtube.com", "example.org", " "})
	if n != 1 || got != "discord.com\nYouTube.com\nexample.org" {
		t.Errorf("mergeList = %q, +%d", got, n)
	}
}

func TestTargetsFile(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "utils"), 0o755)
	os.WriteFile(filepath.Join(dir, "utils", "targets.txt"), []byte("A = \"https://a.example/x\"\r\nB = \"PING:1.1.1.1\"\n# c\n"), 0o644)
	ts := LoadTargets(dir)
	if len(ts) != 2 || ts[0].Host != "a.example" || !ts[1].PingOnly || ts[1].Host != "1.1.1.1" {
		t.Errorf("targets.txt разобран неверно: %+v", ts)
	}
	if len(DefaultTargets) != len(defaultTargetLines) || DefaultTargets[0].Host != "discord.com" {
		t.Errorf("набор по умолчанию: %+v", DefaultTargets[:2])
	}
}

// SSH недоступен: тест останавливается до любых изменений на роутере
// и подсказывает, что именно проверить.
func TestRunUnreachableRouter(t *testing.T) {
	r := &fakeRouter{conf: "ORIGINAL CONF", lists: map[string]string{}}
	r.failConf = errTest("SSH-подключение к 192.168.1.1:222: dial tcp 192.168.1.1:222: connectex: No connection could be made because the target machine actively refused it")
	o := testOpts(t, "http://127.0.0.1:1")
	o.OnJournal = func(*Journal) {}

	rep := Run(context.Background(), r, o)

	if rep.Touched || rep.Restored || len(r.events) != 0 {
		t.Errorf("недоступный роутер не должен трогаться: touched=%v restored=%v events=%v", rep.Touched, rep.Restored, r.events)
	}
	if !strings.Contains(rep.Fatal, "refused") || !strings.Contains(rep.Fatal, "exec sh") {
		t.Errorf("ошибка без причины или подсказки: %s", rep.Fatal)
	}
}

func TestPingBatch(t *testing.T) {
	res := PingBatch(context.Background(), []string{"127.0.0.1", "127.0.0.2"}, time.Second)
	for _, h := range []string{"127.0.0.1", "127.0.0.2"} {
		if !res[h].OK || res[h].MS > 50 {
			t.Errorf("%s: %+v, want быстрый ответ", h, res[h])
		}
	}
}
