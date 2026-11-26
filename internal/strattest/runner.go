package strattest

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"f2n/internal/convert"
)

// Пути на роутере.
const (
	ConfPath = "/opt/etc/nfqws2/nfqws2.conf"
	UserList = "/opt/etc/nfqws2/lists/user.list"
	AutoList = "/opt/etc/nfqws2/lists/auto.list"
)

// settle — пауза после старта службы, пока демон поднимается и правила встают на место.
const settle = 2 * time.Second

// Router — что оркестратору нужно от роутера. Настоящая реализация — по SSH
// (gui/sshrouter.go), в тестах — записывающий дубль.
type Router interface {
	Conf() (string, error)       // текущий nfqws2.conf
	Backup() (string, error)     // копия конфига на роутере; возвращает её путь
	WriteConf(conf string) error // запись с проверкой чтением
	Restart() error              // перезапуск; ошибка, если служба не поднялась
	Stop() error                 // остановка (уже остановлена — не ошибка)
	Start() error                // запуск; ошибка, если служба не поднялась
	ReadFile(path string) (string, error)
	WriteFile(path, content string) error
}

type Options struct {
	Convert    convert.Options // папка Flowseal, интерфейс, политика, Game Filter
	Strategies []string        // имена .bat-пресетов (с расширением или без)
	Baseline   bool            // сначала замер с остановленным nfqws2 — что заблокировано без обхода
	DPI        bool            // проверка «TCP 16-20 freeze»
	Rounds     int             // повторов стандартной проверки (1..5)
	Timeout    time.Duration   // таймаут одного запроса (по умолчанию 4 с)
	DPIHosts   []DPIHost       // пусто — загрузить набор при запуске
	Targets    []Target        // пусто — utils/targets.txt Flowseal или набор по умолчанию
	Progress   func(Progress)
	Cancel     <-chan struct{} // закрыть, чтобы остановиться после текущей стратегии
	OnJournal  func(*Journal)  // nil после восстановления
	Sleep      func(time.Duration)
}

type Progress struct {
	Step, Total int
	Msg         string `json:"msg"`
}

// Journal — что вернуть на место, если сессия оборвётся посреди теста.
type Journal struct {
	Backup  string            `json:"backup"`
	Started time.Time         `json:"started"`
	Conf    string            `json:"conf"`
	Lists   map[string]string `json:"lists"`
}

type TargetResult struct {
	Name     string `json:"name"`
	URL      string `json:"url"`
	PingOnly bool   `json:"pingOnly"`
	HTTP     string `json:"http"`
	TLS12    string `json:"tls12"`
	TLS13    string `json:"tls13"`
	PingOK   bool   `json:"pingOk"`
	PingMS   int    `json:"pingMs"`
	OKRounds [3]int `json:"okRounds"`
}

func (t TargetResult) statuses() []string { return []string{t.HTTP, t.TLS12, t.TLS13} }

type DPIResult struct {
	ID       string `json:"id"`
	Provider string `json:"provider"`
	Country  string `json:"country"`
	Host     string `json:"host"`
	HTTP     string `json:"http"`
	TLS12    string `json:"tls12"`
	TLS13    string `json:"tls13"`
}

func (d DPIResult) statuses() []string { return []string{d.HTTP, d.TLS12, d.TLS13} }

// StrategyResult — итог одной стратегии (или базового замера).
type StrategyResult struct {
	Name          string         `json:"name"`
	Started       bool           `json:"started"` // nfqws2 поднялся с этим конфигом
	Note          string         `json:"note"`
	Targets       []TargetResult `json:"targets"`
	DPI           []DPIResult    `json:"dpi"`
	StandardOK    int            `json:"standardOk"`
	StandardTotal int            `json:"standardTotal"`
	SSL           int            `json:"ssl"`
	PingOK        int            `json:"pingOk"`
	DPIOK         int            `json:"dpiOk"`
	DPIBlocked    int            `json:"dpiBlocked"`
	DPITotal      int            `json:"dpiTotal"`
	Unblocked     int            `json:"unblocked"` // было заблокировано без обхода, теперь открывается
	Broken        int            `json:"broken"`    // открывалось без обхода, теперь нет
	Score         int            `json:"score"`     // совокупный итог, 0..100
	Quality       int            `json:"quality"`   // доля удачных попыток, %
	Rank          int            `json:"rank"`
	Best          bool           `json:"best"`
	rounds        int            // сколько прогонов фактически выполнено
}

func (s *StrategyResult) tokens() []string {
	var out []string
	for _, t := range s.Targets {
		if !t.PingOnly {
			out = append(out, t.statuses()...)
		}
	}
	for _, d := range s.DPI {
		out = append(out, d.statuses()...)
	}
	return out
}

type Report struct {
	Started   time.Time         `json:"started"`
	DurationS int               `json:"durationS"`
	Baseline  *StrategyResult   `json:"baseline"`
	Results   []*StrategyResult `json:"results"`
	Warnings  []string          `json:"warnings"`
	Restored  bool              `json:"restored"` // конфиг и списки роутера возвращены на место
	Touched   bool              `json:"touched"`  // тест успел что-то изменить на роутере
	Fatal     string            `json:"fatal"`
	Cancelled bool              `json:"cancelled"`
	WithDPI   bool              `json:"withDpi"`
}

// Run по очереди ставит каждую стратегию на роутер и проверяет её с этого ПК.
// Независимо от исхода возвращает прежний конфиг и списки на место.
func Run(ctx context.Context, r Router, o Options) *Report {
	rep := &Report{Started: time.Now(), WithDPI: o.DPI}
	if o.Sleep == nil {
		o.Sleep = time.Sleep
	}
	if o.Timeout <= 0 {
		o.Timeout = 4 * time.Second
	}
	if o.Rounds < 1 {
		o.Rounds = 1
	}
	if o.Rounds > 5 {
		o.Rounds = 5
	}
	if len(o.Targets) == 0 {
		o.Targets = LoadTargets(o.Convert.FlowsealDir)
	}
	rep.Warnings = append(rep.Warnings, Diagnostics()...)
	if o.DPI && len(o.DPIHosts) == 0 {
		hosts, err := LoadDPISuite(ctx)
		if err != nil {
			rep.Warnings = append(rep.Warnings, "Набор DPI checkers недоступен ("+err.Error()+") — проверка freeze пропущена")
			o.DPI, rep.WithDPI = false, false
		} else {
			o.DPIHosts = hosts
		}
	}
	cancelled := func() bool {
		select {
		case <-o.Cancel:
			return true
		default:
			return false
		}
	}
	total := 2 + 2*len(o.Strategies)
	if o.Baseline {
		total++
	}
	step := 0
	say := func(format string, a ...interface{}) {
		step++
		if o.Progress != nil {
			o.Progress(Progress{Step: step, Total: total, Msg: fmt.Sprintf(format, a...)})
		}
	}
	done := func() {
		rep.DurationS = int(time.Since(rep.Started).Round(time.Second) / time.Second)
	}

	orig, err := r.Conf()
	if err != nil {
		rep.Fatal = "Не удалось прочитать конфиг роутера: " + err.Error() + sshHint(err.Error())
		done()
		return rep
	}
	say("Бэкап текущего конфига роутера")
	bak, err := r.Backup()
	if err != nil {
		rep.Fatal = "Не удалось сохранить бэкап конфига: " + err.Error()
		done()
		return rep
	}
	// списки читаются до любых изменений: автохостлист пополняется и при неудачных проверках
	lists := map[string]string{}
	for _, p := range []string{UserList, AutoList} {
		lists[p], _ = r.ReadFile(p)
	}
	if o.OnJournal != nil {
		o.OnJournal(&Journal{Backup: bak, Started: rep.Started, Conf: orig, Lists: lists})
	}

	restore := func() {
		say("Восстановление прежнего конфига роутера")
		for p, c := range lists {
			if err := r.WriteFile(p, c); err != nil {
				rep.Warnings = append(rep.Warnings, fmt.Sprintf("Не удалось вернуть %s: %v", filepath.Base(p), err))
			}
		}
		if err := r.WriteConf(orig); err != nil {
			rep.Fatal = "НЕ УДАЛОСЬ ВЕРНУТЬ КОНФИГ РОУТЕРА (" + err.Error() + "). Прежний конфиг сохранён на роутере: " + bak
			return
		}
		if err := r.Restart(); err != nil {
			rep.Fatal = "КОНФИГ ВОЗВРАЩЁН, но nfqws2 не поднялся (" + firstLine(err.Error()) + "). Перезапустите службу вручную: /opt/etc/init.d/S51nfqws2 restart"
			return
		}
		rep.Restored = true
		if o.OnJournal != nil {
			o.OnJournal(nil)
		}
	}

	if o.Baseline && !cancelled() {
		say("Базовый замер: nfqws2 остановлен")
		rep.Touched = true
		if err := r.Stop(); err != nil {
			rep.Warnings = append(rep.Warnings, "Не удалось остановить nfqws2 для базового замера: "+firstLine(err.Error()))
		} else {
			o.Sleep(time.Second)
			rep.Baseline = &StrategyResult{Name: "Без обхода"}
			measure(ctx, &o, rep.Baseline)
			if err := r.Start(); err != nil {
				rep.Warnings = append(rep.Warnings, "nfqws2 не поднялся после базового замера: "+firstLine(err.Error()))
			}
			o.Sleep(settle)
		}
	}

	// на время теста стратегия должна применяться к проверочным доменам
	if merged, n := mergeList(lists[UserList], testDomains(o.Targets, o.DPIHosts)); n > 0 {
		rep.Touched = true
		if err := r.WriteFile(UserList, merged); err != nil {
			rep.Warnings = append(rep.Warnings, "Не удалось дополнить user.list на время теста: "+firstLine(err.Error()))
		}
	}

	for _, name := range o.Strategies {
		if cancelled() {
			rep.Cancelled = true
			break
		}
		say("Стратегия %s: установка на роутер", name)
		res := &StrategyResult{Name: name}
		opts := o.Convert
		opts.BatFile = filepath.Join(o.Convert.FlowsealDir, batName(name, o.Convert.FlowsealDir))
		conv, err := convert.Run(opts)
		switch {
		case err != nil:
			res.Note = "Ошибка конвертации: " + err.Error()
		case len(conv.Warnings) > 0:
			res.Note = "Конвертация с предупреждениями: " + strings.Join(conv.Warnings, "; ")
		}
		if res.Note == "" {
			rep.Touched = true
			if err := r.WriteConf(conv.Conf); err != nil {
				res.Note = "Не удалось записать конфиг: " + firstLine(err.Error())
			} else if err := r.Restart(); err != nil {
				res.Note = "nfqws2 не запустился с этой стратегией: " + firstLine(err.Error())
				// службу нужно поднять сразу: иначе обход пропадает у всей сети
				if werr := r.WriteConf(orig); werr == nil {
					_ = r.Start()
				}
			} else {
				res.Started = true
				o.Sleep(settle)
				say("Стратегия %s: проверки", name)
				measure(ctx, &o, res)
			}
		}
		rep.Results = append(rep.Results, res)
	}
	restore()
	rep.finish()
	done()
	return rep
}

// batName дополняет имя пресета расширением и проверяет, что файл есть в папке.
func batName(name, dir string) string {
	if !strings.HasSuffix(strings.ToLower(name), ".bat") {
		name += ".bat"
	}
	return name
}

// testDomains — домены проверочных целей: их нужно добавить в user.list,
// иначе в режиме автохостлиста стратегия применяется к ним не сразу.
func testDomains(targets []Target, dpi []DPIHost) []string {
	var out []string
	for _, t := range targets {
		if t.Host != "" {
			out = append(out, t.Host)
		}
	}
	for _, d := range dpi {
		out = append(out, d.Host)
	}
	return out
}

// mergeList дополняет список доменами, которых в нём нет.
func mergeList(cur string, add []string) (string, int) {
	seen := map[string]bool{}
	var lines []string
	for _, ln := range strings.Split(cur, "\n") {
		ln = strings.TrimRight(ln, "\r")
		lines = append(lines, ln)
		if t := strings.ToLower(strings.TrimSpace(ln)); t != "" {
			seen[t] = true
		}
	}
	var fresh []string
	for _, d := range add {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		fresh = append(fresh, d)
	}
	// завершающий перенос строки не должен стать пустой строкой посреди списка
	if len(fresh) > 0 && len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	lines = append(lines, fresh...)
	return strings.Join(lines, "\n"), len(fresh)
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// sshHint подсказывает, что проверить, когда SSH роутера недоступен.
func sshHint(err string) string {
	e := strings.ToLower(err)
	switch {
	case strings.Contains(e, "refused"):
		return ". Порт SSH закрыт — на роутере не запущен SSH-сервер Entware (порт 222) или указан не тот порт. " +
			"На Keenetic его можно поднять через встроенный SSH (порт 22, логин admin): войти командой «exec sh» и запустить dropbear " +
			"(/opt/etc/init.d/S51dropbear start), либо перезагрузить роутер."
	case strings.Contains(e, "timeout"), strings.Contains(e, "i/o timeout"), strings.Contains(e, "deadline"):
		return ". Роутер не отвечает — проверьте адрес, порт и кабель/сеть."
	case strings.Contains(e, "password"), strings.Contains(e, "auth"), strings.Contains(e, "handshake"):
		return ". Проверьте логин и пароль SSH."
	}
	return ""
}

// measure прогоняет стандартные проверки (по Rounds раз) и набор DPI.
func measure(ctx context.Context, o *Options, res *StrategyResult) {
	rounds := o.Rounds
	res.rounds = rounds
	type acc struct {
		ok, ssl [3]atomic.Int32
		pingOK  atomic.Int32
		pingMS  atomic.Int64
	}
	accs := make([]acc, len(o.Targets))
	for i := range accs {
		accs[i].pingMS.Store(1 << 62)
	}
	hosts := make([]string, len(o.Targets))
	for i, t := range o.Targets {
		hosts[i] = t.Host
	}
	for round := 0; round < rounds && ctx.Err() == nil; round++ {
		// ping всех целей — одним пакетом, параллельно с HTTP-проверками
		pingCh := make(chan map[string]PingResult, 1)
		go func() { pingCh <- PingBatch(ctx, hosts, time.Second) }()
		parallel(ctx, 8, len(o.Targets), func(i int) {
			t := o.Targets[i]
			if t.PingOnly {
				return
			}
			var wg sync.WaitGroup
			for k := range Modes {
				wg.Add(1)
				go func(k int) {
					defer wg.Done()
					s := CheckURL(ctx, t.URL, Modes[k], o.Timeout)
					if s == "" {
						return // отменено
					}
					if s == StatusOK {
						accs[i].ok[k].Add(1)
					} else if s == StatusSSL {
						accs[i].ssl[k].Add(1)
					}
				}(k)
			}
			wg.Wait()
		})
		pings := <-pingCh
		for i, t := range o.Targets {
			p := pings[t.Host]
			if !p.OK {
				continue
			}
			accs[i].pingOK.Add(1)
			for old := accs[i].pingMS.Load(); int64(p.MS) < old && !accs[i].pingMS.CompareAndSwap(old, int64(p.MS)); old = accs[i].pingMS.Load() {
			}
		}
	}
	res.Targets = make([]TargetResult, len(o.Targets))
	for i, t := range o.Targets {
		tr := TargetResult{Name: t.Name, URL: t.URL, PingOnly: t.PingOnly}
		st := []*string{&tr.HTTP, &tr.TLS12, &tr.TLS13}
		for k := range Modes {
			n := int(accs[i].ok[k].Load())
			tr.OKRounds[k] = n
			switch {
			case t.PingOnly:
				*st[k] = ""
			case n*2 > rounds: // строго больше половины удачных прогонов
				*st[k] = StatusOK
			case accs[i].ssl[k].Load() > 0:
				*st[k] = StatusSSL
			default:
				*st[k] = StatusError
			}
		}
		if tr.PingOK = accs[i].pingOK.Load() > 0; tr.PingOK {
			tr.PingMS = int(accs[i].pingMS.Load())
		}
		res.Targets[i] = tr
	}
	if len(o.DPIHosts) > 0 && ctx.Err() == nil {
		res.DPI = make([]DPIResult, len(o.DPIHosts))
		timeout := o.Timeout + time.Second
		parallel(ctx, 8, len(o.DPIHosts), func(i int) {
			d := o.DPIHosts[i]
			r := DPIResult{ID: d.ID, Provider: d.Provider, Country: d.Country, Host: d.Host}
			for k, mode := range Modes {
				*[]*string{&r.HTTP, &r.TLS12, &r.TLS13}[k] = CheckDPI(ctx, d.Host, mode, timeout)
			}
			res.DPI[i] = r
		})
	}
}

// score — совокупный итог: стандартные проверки (Discord, YouTube...) с весом 70%
// и устойчивость к freeze из DPI checkers с весом 30%; без DPI — только стандартные.
func score(s *StrategyResult, withDPI bool) int {
	if s.StandardTotal == 0 {
		return 0 // служба не поднялась или проверок не было
	}
	std := 100 * s.StandardOK / s.StandardTotal
	if !withDPI || s.DPITotal == 0 {
		return std
	}
	dpi := 100 * s.DPIOK / s.DPITotal
	return (7*std + 3*dpi) / 10
}

// finish считает итоги, сравнивает с базовым замером и выстраивает стратегии по рангу.
func (rep *Report) finish() {
	all := rep.Results
	if rep.Baseline != nil {
		all = append([]*StrategyResult{rep.Baseline}, all...)
	}
	for _, s := range all {
		var okRounds, attempts int
		for _, t := range s.Targets {
			if t.PingOK {
				s.PingOK++
			}
			if t.PingOnly {
				continue
			}
			attempts += 3 * s.rounds
			for k, st := range t.statuses() {
				s.StandardTotal++
				okRounds += t.OKRounds[k]
				if st == StatusOK {
					s.StandardOK++
				} else if st == StatusSSL {
					s.SSL++
				}
			}
		}
		if attempts > 0 {
			s.Quality = 100 * okRounds / attempts
		}
		for _, d := range s.DPI {
			for _, st := range d.statuses() {
				s.DPITotal++
				switch st {
				case StatusOK:
					s.DPIOK++
				case StatusBlocked:
					s.DPIBlocked++
				}
			}
		}
		s.Score = score(s, rep.WithDPI)
	}
	// базовый замер показывает, что действительно заблокировано; он же выявляет,
	// что стратегия ломает из того, что открывалось без обхода
	if base := rep.Baseline; base != nil {
		bt := base.tokens()
		for _, s := range rep.Results {
			st := s.tokens()
			for i := 0; i < len(bt) && i < len(st); i++ {
				switch {
				case bt[i] != StatusOK && st[i] == StatusOK:
					s.Unblocked++
				case bt[i] == StatusOK && st[i] != StatusOK:
					s.Broken++
				}
			}
		}
	}
	sort.SliceStable(rep.Results, func(i, j int) bool {
		a, b := rep.Results[i], rep.Results[j]
		switch {
		case a.Started != b.Started:
			return a.Started
		case a.Score != b.Score:
			return a.Score > b.Score
		case a.Broken != b.Broken:
			return a.Broken < b.Broken
		case a.Unblocked != b.Unblocked:
			return a.Unblocked > b.Unblocked
		default:
			return a.Quality > b.Quality
		}
	})
	for i, s := range rep.Results {
		s.Rank = i + 1
	}
	if len(rep.Results) > 0 && rep.Results[0].Started {
		rep.Results[0].Best = true
	}
}
