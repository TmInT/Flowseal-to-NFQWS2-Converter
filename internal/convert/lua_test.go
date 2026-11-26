package convert

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/yuin/gopher-lua"
)

// Сгенерированный конфиг выполняется на Lua-библиотеках zapret2. Здесь те же
// библиотеки (testdata/zapret2-lua, версия роутера) грузятся в настоящую VM,
// а C-функции nfqws2 заменены записывающими дублями. Так проверяется реальное
// поведение инстансов на проводе: что, в каком порядке и с какими искажениями уйдёт.

const (
	luaLibDir = "../../testdata/zapret2-lua"
	// тестовый пейлоад: 100 байт, хост, хвост
	testHost    = "www.youtube.com"
	luaVerdicts = "VERDICT_PASS=0 VERDICT_MODIFY=1 VERDICT_DROP=2"
)

func testPayload() string {
	return strings.Repeat("x", 100) + testHost + strings.Repeat("y", 185)
}

type luaSend struct {
	payload string
	seq     int
	fooling string // непустые fooling-аргументы отправки
}

// luaFoolingKeys — аргументы, которые apply_fooling реально применяет к заголовкам.
var luaFoolingKeys = map[string]bool{
	"ip_ttl": true, "ip6_ttl": true, "ip_autottl": true, "ip6_autottl": true,
	"ip6_hopbyhop": true, "ip6_hopbyhop2": true, "ip6_destopt": true, "ip6_destopt2": true, "ip6_routing": true, "ip6_ah": true,
	"tcp_seq": true, "tcp_ack": true, "tcp_ts": true, "tcp_md5": true, "tcp_flags_set": true, "tcp_flags_unset": true,
	"tcp_ts_up": true, "tcp_nop_del": true,
}

type luaVM struct {
	t       *testing.T
	L       *lua.LState
	sends   []luaSend
	tlsMods []string // вызовы tls_mod при старте
}

func newLuaVM(t *testing.T) *luaVM {
	t.Helper()
	v := &luaVM{t: t, L: lua.NewState()}
	L := v.L
	t.Cleanup(L.Close)
	L.SetGlobal("b_debug", lua.LFalse)
	L.SetGlobal("NFQWS2_COMPAT_VER", lua.LNumber(6)) // версия C-интерфейса zapret2 v1.0.7
	for _, c := range strings.Fields(luaVerdicts) {
		k, val, _ := strings.Cut(c, "=")
		n, _ := strconv.Atoi(val)
		L.SetGlobal(k, lua.LNumber(n))
	}
	for name, n := range map[string]int{"TH_FIN": 1, "TH_SYN": 2, "TH_RST": 4, "TH_PUSH": 8, "TH_ACK": 16, "TH_URG": 32} {
		L.SetGlobal(name, lua.LNumber(n))
	}
	noop := L.NewFunction(func(L *lua.LState) int { L.Push(lua.LNil); return 1 })
	// числовые заглушки: библиотека при загрузке считает из них сид генератора
	one := L.NewFunction(func(L *lua.LState) int { L.Push(lua.LNumber(1)); return 1 })
	for _, n := range []string{"bitnot", "bitand", "bitor", "bitxor", "getpid", "gettid", "clock_gettime"} {
		L.SetGlobal(n, one)
	}
	for _, n := range []string{"instance_cutoff", "DLOG"} {
		L.SetGlobal(n, noop)
	}
	for _, n := range []string{"brandom_az", "brandom_az09"} {
		L.SetGlobal(n, L.NewFunction(func(L *lua.LState) int {
			L.Push(lua.LString(strings.Repeat("a", L.CheckInt(1))))
			return 1
		}))
	}
	L.SetGlobal("parse_hex", L.NewFunction(func(L *lua.LState) int {
		b, err := hex.DecodeString(L.CheckString(1))
		if err != nil {
			t.Fatalf("parse_hex: %v", err)
		}
		L.Push(lua.LString(b))
		return 1
	}))
	L.SetGlobal("divint", L.NewFunction(func(L *lua.LState) int {
		L.Push(lua.LNumber(L.CheckInt(1) / L.CheckInt(2)))
		return 1
	}))
	L.SetGlobal("tls_mod", L.NewFunction(func(L *lua.LState) int {
		v.tlsMods = append(v.tlsMods, L.CheckString(1)+":"+L.CheckString(2))
		L.Push(L.Get(1)) // содержимое не проверяем: важен сам вызов при старте
		return 1
	}))

	// позиции маркеров: 1-based, как отдаёт C-код nfqws2
	markers := map[string]int{"host": 101, "endhost": 116, "sld": 105, "endsld": 112, "midsld": 108, "sniext": 60}
	resolve := func(data, mk string) (int, bool) {
		base, off := mk, 0
		if i := strings.IndexAny(mk, "+-"); i > 0 {
			off, _ = strconv.Atoi(mk[i:])
			base = mk[:i]
		}
		var pos int
		if n, err := strconv.Atoi(base); err == nil {
			if n > 0 {
				pos = n
			} else {
				pos = len(data) + 1 + n
			}
		} else {
			p, ok := markers[base]
			if !ok {
				return 0, false
			}
			pos = p
		}
		pos += off
		if pos < 1 || pos > len(data) {
			return 0, false
		}
		return pos, true
	}
	list := func(L *lua.LState) (string, []string) {
		data := L.CheckString(1)
		var ms []string
		for _, m := range strings.Split(L.CheckString(3), ",") {
			if m = strings.TrimSpace(m); m != "" {
				ms = append(ms, m)
			}
		}
		return data, ms
	}
	L.SetGlobal("resolve_pos", L.NewFunction(func(L *lua.LState) int {
		data, ms := list(L)
		if len(ms) != 1 {
			t.Fatalf("resolve_pos: ожидался один маркер, получено %v", ms)
		}
		if p, ok := resolve(data, ms[0]); ok {
			L.Push(lua.LNumber(p))
		} else {
			L.Push(lua.LNil)
		}
		return 1
	}))
	L.SetGlobal("resolve_multi_pos", L.NewFunction(func(L *lua.LState) int {
		data, ms := list(L)
		seen := map[int]bool{}
		var pos []int
		for _, m := range ms {
			if p, ok := resolve(data, m); ok && !seen[p] {
				seen[p] = true
				pos = append(pos, p)
			}
		}
		sort.Ints(pos)
		tbl := L.NewTable()
		for i, p := range pos {
			tbl.RawSetInt(i+1, lua.LNumber(p))
		}
		L.Push(tbl)
		return 1
	}))
	L.SetGlobal("resolve_range", L.NewFunction(func(L *lua.LState) int {
		data, ms := list(L)
		if len(ms) != 2 {
			t.Fatalf("resolve_range: ожидалось два маркера, получено %v", ms)
		}
		p1, ok1 := resolve(data, ms[0])
		p2, ok2 := resolve(data, ms[1])
		if !ok1 || !ok2 {
			L.Push(lua.LNil)
			return 1
		}
		tbl := L.NewTable()
		tbl.RawSetInt(1, lua.LNumber(p1))
		tbl.RawSetInt(2, lua.LNumber(p2))
		L.Push(tbl)
		return 1
	}))
	rs := L.NewFunction(func(L *lua.LState) int {
		s := luaSend{payload: L.CheckString(2), seq: int(L.OptInt(3, 0))}
		if opt, ok := L.Get(4).(*lua.LTable); ok {
			if f, ok := L.GetField(opt, "fooling").(*lua.LTable); ok {
				var kv []string
				f.ForEach(func(k, val lua.LValue) {
					if s := lua.LVAsString(val); s != "" && luaFoolingKeys[lua.LVAsString(k)] {
						kv = append(kv, lua.LVAsString(k)+"="+s)
					}
				})
				sort.Strings(kv)
				s.fooling = strings.Join(kv, ",")
			}
		}
		v.sends = append(v.sends, s)
		L.Push(lua.LTrue)
		return 1
	})
	// библиотеки грузятся один раз на VM: компиляция занимает около секунды
	v.loadLib("zapret-lib.lua")
	v.loadLib("zapret-antidpi.lua")
	// отправку библиотека определяет сама — подменяем записывающим дублями
	L.SetGlobal("rawsend_payload_segmented", rs)
	L.SetGlobal("rawsend_dissect_segmented", rs)
	return v
}

// loadLib грузит штатную библиотеку. Отличия от оригинала — только то, чего не
// понимает тестовая VM (Lua 5.1 вместо LuaJIT): goto в dissect_tls заменён на break,
// hex-экранирование "\xNN" — на десятичное "\d{3}". На проверяемые пути не влияет.
var reLuaHexEsc = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)

func (v *luaVM) loadLib(name string) {
	v.t.Helper()
	src, err := os.ReadFile(filepath.Join(luaLibDir, name))
	if err != nil {
		v.t.Fatal(err)
	}
	code := strings.ReplaceAll(strings.ReplaceAll(string(src), "goto endrec", "break"), "::endrec::", "")
	code = reLuaHexEsc.ReplaceAllStringFunc(code, func(m string) string {
		n, _ := strconv.ParseInt(m[2:], 16, 32)
		return `\` + strconv.FormatInt(n, 10)
	})
	if strings.Contains(code, "goto ") || reLuaHexEsc.MatchString(code) {
		v.t.Fatalf("%s: в библиотеке появился ещё один goto", name)
	}
	if err := v.L.DoString(code); err != nil {
		v.t.Fatalf("%s: %v", name, err)
	}
}

var (
	reBlobLine = regexp.MustCompile(`(?m)^\s*--blob=([a-z0-9_]+):0x([0-9a-fA-F]+)\s*$`)
	reInitLine = regexp.MustCompile(`(?m)^\s*--lua-init=([^@\s"][^\s"]*)\s*"?$`)
	reDesync   = regexp.MustCompile(`--lua-desync=([^\s"]+)`)
)

// loadConf повторяет запуск nfqws2: блобы становятся глобальными переменными,
// затем выполняются lua-init строки конфига.
func (v *luaVM) loadConf(conf string) []string {
	v.t.Helper()
	for _, m := range reBlobLine.FindAllStringSubmatch(conf, -1) {
		b, err := hex.DecodeString(m[2])
		if err != nil {
			v.t.Fatalf("blob %s: %v", m[1], err)
		}
		v.L.SetGlobal(m[1], lua.LString(b))
	}
	for _, m := range reInitLine.FindAllStringSubmatch(conf, -1) {
		if err := v.L.DoString(m[1]); err != nil {
			v.t.Fatalf("lua-init %s: %v", m[1], err)
		}
	}
	var out []string
	for _, m := range reDesync.FindAllStringSubmatch(conf, -1) {
		out = append(out, m[1])
	}
	return out
}

func (v *luaVM) fn(line string) string {
	fn, _, _ := strings.Cut(line, ":")
	return fn
}

// run вызывает инстанс "--lua-desync=fn:k=v:flag" на тестовом пейлоаде.
func (v *luaVM) run(line, l7 string) int {
	v.t.Helper()
	L := v.L
	fn, argstr, _ := strings.Cut(line, ":")
	d := L.NewTable()
	dis := L.NewTable()
	tcp := L.NewTable()
	tcp.RawSetString("th_flags", lua.LNumber(24))
	tcp.RawSetString("th_seq", lua.LNumber(1000))
	dis.RawSetString("tcp", tcp)
	dis.RawSetString("payload", lua.LString(testPayload()))
	d.RawSetString("dis", dis)
	d.RawSetString("l7payload", lua.LString(l7))
	d.RawSetString("outgoing", lua.LTrue)
	d.RawSetString("func_instance", lua.LString(fn))
	arg := L.NewTable()
	for _, kv := range strings.Split(argstr, ":") {
		if kv == "" {
			continue
		}
		k, val, _ := strings.Cut(kv, "=")
		arg.RawSetString(k, lua.LString(val))
	}
	d.RawSetString("arg", arg)
	f := L.GetGlobal(fn)
	if _, ok := f.(*lua.LFunction); !ok {
		v.t.Fatalf("функция %s не определена", fn)
	}
	if err := L.CallByParam(lua.P{Fn: f, NRet: 1, Protect: true}, lua.LNil, d); err != nil {
		v.t.Fatalf("%s: %v", line, err)
	}
	res := L.Get(-1)
	L.Pop(1)
	if res == lua.LNil {
		return -1
	}
	return int(lua.LVAsNumber(res))
}

func mustLine(t *testing.T, lines []string, sub string) string {
	t.Helper()
	for _, l := range lines {
		if strings.Contains(l, sub) {
			return l
		}
	}
	t.Fatalf("в конфиге нет инстанса %q среди %d", sub, len(lines))
	return ""
}

// Позиция разреза: с pos=2 запрос режется после первого байта, с pos=1 — нет.
func TestLuaSplitPosition(t *testing.T) {
	v := newLuaVM(t)
	lines := v.loadConf(runPreset(t, "general (ALT11)", "all").Conf)
	line := mustLine(t, lines, "multisplit:pos=2:seqovl=664:seqovl_pattern=tls_clienthello_www_sferum_ru")
	if verdict := v.run(line, "tls_client_hello"); verdict != 2 || len(v.sends) != 2 {
		t.Fatalf("verdict=%d sends=%d, want DROP и 2 сегмента", verdict, len(v.sends))
	}
	if len(v.sends[0].payload) != 665 || v.sends[0].seq != -664 {
		t.Errorf("первый сегмент: len=%d seq=%d, want 665 и -664 (seqovl)", len(v.sends[0].payload), v.sends[0].seq)
	}
	if v.sends[1].seq != 1 || len(v.sends[1].payload) != 299 {
		t.Errorf("второй сегмент: len=%d seq=%d, want 299 и 1", len(v.sends[1].payload), v.sends[1].seq)
	}
	for _, s := range v.sends {
		if s.fooling != "" {
			t.Errorf("реальный сегмент получил fooling %q", s.fooling)
		}
	}
	// прежний вариант конвертера: позиция "как в winws"
	v.sends = nil
	if verdict := v.run(strings.Replace(line, "pos=2", "pos=1", 1), "tls_client_hello"); verdict != -1 || len(v.sends) != 0 {
		t.Errorf("pos=1 должен ничего не отправлять: verdict=%d sends=%d", verdict, len(v.sends))
	}
}

// Встроенная функция altorder: тот же порядок сегментов, что в winws.
func TestLuaAltorder(t *testing.T) {
	v := newLuaVM(t)
	lines := v.loadConf(runPreset(t, "general (ALT3)", "all").Conf)
	data := testPayload()
	line := mustLine(t, lines, "f2n_hfs_alt:host=www.google.com:tcp_ts=-600000:tcp_ts_up")
	// фейк хоста генерирует штатная genhost: 15 символов по шаблону "google.com" → "aaaa.google.com"
	// (заглушки генератора возвращают "a")
	line = strings.Replace(line, "host=www.google.com", "host=google.com", 1)
	if verdict := v.run(line, "tls_client_hello"); verdict != 2 || len(v.sends) != 4 {
		t.Fatalf("verdict=%d sends=%d, want DROP и 4 сегмента", verdict, len(v.sends))
	}
	// до хоста, фейк хоста, после хоста, реальный хост
	want := []luaSend{
		{data[:100], 0, ""},
		{"aaaa.google.com", 100, "tcp_ts=-600000"},
		{data[115:], 115, ""},
		{data[100:115], 100, ""},
	}
	for i := range want {
		if v.sends[i] != want[i] {
			t.Errorf("сегмент %d = %+v, want %+v", i, v.sends[i], want[i])
		}
	}
	v.sends = nil
	v.run(line+":midhost=midsld", "tls_client_hello")
	if len(v.sends) != 5 || v.sends[3].payload != data[100:107] || v.sends[4].payload != data[107:115] || v.sends[4].seq != 107 {
		t.Errorf("midhost должен резать реальный хост на две части: %+v", v.sends)
	}
	v.sends = nil
	if verdict := v.run(line, "unknown"); verdict != -1 || len(v.sends) != 0 {
		t.Errorf("без имени хоста пакет должен уходить как есть: verdict=%d sends=%d", verdict, len(v.sends))
	}
}

// fakedsplit: fooling получают только фейки, реальные части уходят чистыми.
func TestLuaFakedsplitFooling(t *testing.T) {
	v := newLuaVM(t)
	lines := v.loadConf(runPreset(t, "general (FAKE TLS AUTO ALT)", "all").Conf)
	// badseq-increment=2 из пресета → tcp_seq=2
	line := mustLine(t, lines, "fakedsplit:pos=2:tcp_seq=2:tcp_ack=-66000:tcp_ts_up")
	if verdict := v.run(line, "tls_client_hello"); verdict != 2 || len(v.sends) != 6 {
		t.Fatalf("verdict=%d sends=%d, want DROP и 6 отправок", verdict, len(v.sends))
	}
	for i, s := range v.sends {
		real := i == 1 || i == 4 // порядок: фейк, оригинал, фейк, фейк, оригинал, фейк
		if real && (s.fooling != "" || s.payload == strings.Repeat("\x00", len(s.payload))) {
			t.Errorf("отправка %d: оригинал с искажением или фейк вместо оригинала: %+v", i, s)
		}
		if !real && s.fooling != "tcp_ack=-66000,tcp_seq=2" {
			t.Errorf("отправка %d: фейк без fooling: %+v", i, s)
		}
	}
}

// Каждый инстанс каждого пресета — существующая функция библиотек.
func TestLuaEveryInstanceResolves(t *testing.T) {
	v := newLuaVM(t)
	for _, name := range presetNames(t) {
		lines := v.loadConf(runPreset(t, name, "all").Conf)
		for _, l := range lines {
			if _, ok := v.L.GetGlobal(v.fn(l)).(*lua.LFunction); !ok {
				t.Errorf("%s: неизвестная функция %s", name, v.fn(l))
			}
		}
	}
}
