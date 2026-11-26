package convert

import (
	_ "embed"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"f2n/internal/flowseal"
)

//go:embed altorder.lua
var altorderLuaRaw string

// altorderLua — исходник с нормализованными переводами строк. Он уходит в конфиг
// hex'ом, поэтому байты не должны зависеть от того, с какими переводами строк
// файл выгрузил git (на CI под Windows это CRLF).
var altorderLua = strings.ReplaceAll(altorderLuaRaw, "\r\n", "\n")

// altorderInit — lua-код функции altorder, встроенный в конфиг одной строкой.
// Шелл init-скрипта делит аргументы по пробелам, поэтому исходник передаётся hex-строкой.
// loadstring есть и в LuaJIT (сборки nfqws2), и в обычной Lua 5.1.
var altorderInit = "assert(loadstring(parse_hex('" + hex.EncodeToString([]byte(altorderLua)) + "')))()"

// fakePayload maps winws fake-source kind to nfqws2 payload name(s).
var fakePayload = map[string]string{
	"tls":        "tls_client_hello",
	"http":       "http_req",
	"quic":       "quic_initial",
	"unknown":    "unknown",
	"unknownudp": "unknown",
	"discord":    "discord_ip_discovery",
	"stun":       "stun",
	"wireguard":  "wireguard_initiation,wireguard_response,wireguard_cookie,wireguard_keepalive",
	"dht":        "dht",
}

// l7ToKind maps --filter-l7 values to fake kinds.
var l7ToKind = map[string]string{
	"http": "http", "tls": "tls", "quic": "quic", "discord": "discord",
	"stun": "stun", "wireguard": "wireguard", "dht": "dht",
}

func zeroBlob(n int) func() []byte { return func() []byte { return make([]byte, n) } }

// defaultFake — что winws подставляет для протокола, если свой фейк не задан.
var defaultFake = map[string]struct {
	name string
	data func() []byte
}{
	"tls":        {"f2n_fake_tls", fakeTLSDefault},
	"http":       {"f2n_fake_http", func() []byte { return []byte(fakeHTTPDefault) }},
	"quic":       {"f2n_fake_quic", fakeQUICDefault},
	"unknown":    {"f2n_fake_z256", zeroBlob(256)},
	"unknownudp": {"f2n_fake_z64", zeroBlob(64)},
	"discord":    {"f2n_fake_z64", zeroBlob(64)},
	"stun":       {"f2n_fake_z64", zeroBlob(64)},
	"wireguard":  {"f2n_fake_z64", zeroBlob(64)},
	"dht":        {"f2n_fake_z64", zeroBlob(64)},
}

// blobStore collects the blobs of a conversion: files from the Flowseal folder and
// built-in fakes. All of them are inlined as hex — the config stays self-sufficient.
type blobStore struct {
	dir   string
	names map[string]string // source abs path -> blob name
	blobs map[string][]byte // blob name -> inline data
	order []string          // blob name, in first-use order
}

func newBlobStore(binDir string) *blobStore {
	return &blobStore{dir: binDir, names: map[string]string{}, blobs: map[string][]byte{}}
}

func (b *blobStore) add(name string, data []byte) {
	if _, ok := b.blobs[name]; ok {
		return
	}
	b.blobs[name] = data
	b.order = append(b.order, name)
}

// blobName resolves a flowseal fake file path to a blob name; registers it if new.
func (b *blobStore) blobName(file string) (string, error) {
	if file == "" {
		return "", fmt.Errorf("empty blob file")
	}
	src := file
	if !filepath.IsAbs(src) {
		if _, err := os.Stat(src); err != nil {
			cand := filepath.Join(b.dir, filepath.Base(src))
			if _, err2 := os.Stat(cand); err2 == nil {
				src = cand
			}
		}
	}
	if _, err := os.Stat(src); err != nil {
		return "", fmt.Errorf("blob file not found: %s", file)
	}
	abs, err := filepath.Abs(src)
	if err != nil {
		return "", err
	}
	if n, ok := b.names[abs]; ok {
		return n, nil
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return "", fmt.Errorf("blob %s: %w", file, err)
	}
	base := strings.ToLower(strings.TrimSuffix(filepath.Base(abs), filepath.Ext(abs)))
	for i := 2; ; i++ {
		if _, exists := b.blobs[base]; !exists {
			break
		}
		base = fmt.Sprintf("%s_%d", base, i)
	}
	b.names[abs] = base
	b.add(base, data)
	return base, nil
}

// inline returns the --blob lines for NFQWS_BASE_ARGS.
func (b *blobStore) inline() []string {
	out := make([]string, 0, len(b.order))
	for _, name := range b.order {
		out = append(out, fmt.Sprintf("--blob=%s:0x%s", name, hex.EncodeToString(b.blobs[name])))
	}
	return out
}

// mapped is the nfqws2 form of one winws profile.
type mapped struct {
	args  []string // --out-range, then --payload + --lua-desync per instance, in order
	core  []string // instance signatures "payload|fn:args" (ipset folding compares them)
	inits []string // --lua-init lines the instances depend on
	alt   bool     // uses the embedded altorder function
	warns []string
	infos []string
}

type warnFunc func(format string, a ...interface{})

// mapProfile converts one winws profile into nfqws2 args.
//
// Правила соответствия (сверены с исходниками zapret1 и Lua-библиотек zapret2):
//   - fooling в winws искажает только фейки; реальные сегменты уходят как есть.
//     В nfqws2 fooling-аргументы применяются ко всему, что отправляет функция,
//     поэтому multisplit/multidisorder их не получают.
//   - позиция разреза: winws задаёт длину первой части (1 = сразу после первого байта),
//     nfqws2 — начало следующей части, поэтому числовые позиции сдвигаются на 1.
//     Маркеры (midsld, host...) в обеих системах указывают на один и тот же байт.
//   - --dpi-desync-cutoff действует на весь профиль, а --out-range в nfqws2 только
//     на последующие инстансы — поэтому он идёт первым.
//   - фейки: winws отправляет все фейки протокола по очереди, каждый repeats раз;
//     если своего фейка нет — встроенный.
func mapProfile(p *flowseal.Profile, b *blobStore) mapped {
	m := mapped{}
	warnf := func(format string, a ...interface{}) { m.warns = append(m.warns, fmt.Sprintf(format, a...)) }

	fooling := foolingArgs(p, warnf)
	ipid := ipIDArgs(p, warnf)
	var repeats []string
	if p.Repeats != "" {
		repeats = []string{"repeats=" + p.Repeats}
	}
	// any-protocol: "по всем непустым пакетам данных"
	anyf, base := "", "known"
	if p.AnyProtocol {
		anyf, base = "payload=~empty", "all"
	}

	if r := rangeArg(p, warnf); r != "" {
		m.args = append(m.args, "--out-range="+r)
	}

	emit := func(payload, fn string, arg ...string) {
		sig := luaJoin(fn, arg...)
		m.args = append(m.args, "--payload="+payload, "--lua-desync="+sig)
		m.core = append(m.core, payload+"|"+sig)
	}

	ref := func(file string) (string, bool) {
		if _, ok := b.blobs[file]; ok {
			return file, true // встроенный фейк, уже зарегистрирован
		}
		if strings.HasPrefix(file, "0x") {
			return file, true // inline hex blob, nfqws2 понимает напрямую
		}
		n, err := b.blobName(file)
		if err != nil {
			warnf("%s — использован blob=0x00000000", err)
			return "0x00000000", false
		}
		return n, true
	}
	// blobArg: "name=<blob>" для файла или hex-строки
	blobArg := func(name, file string) []string {
		if file == "" {
			return nil
		}
		n, ok := ref(file)
		if !ok {
			return nil
		}
		return []string{name + "=" + n}
	}

	// tlsRef: blob для TLS-фейка. Однократные моды (rndsni, sni=) winws применяет
	// при старте — здесь они выполняются в --lua-init; остальные уходят в tls_mod.
	tlsRef := func(f flowseal.Fake) (string, string) {
		name, ok := ref(f.File)
		if f.Kind != "tls" {
			return name, ""
		}
		one, rt := splitTLSMod(f.Mod, warnf)
		if one == "" || !ok {
			return name, rt
		}
		if strings.HasPrefix(name, "0x") {
			raw, _ := hex.DecodeString(strings.TrimPrefix(name, "0x"))
			name = fmt.Sprintf("f2n_hex_%d", len(b.order)+1)
			b.add(name, raw)
		}
		// имя детерминированное: одинаковые моды разных профилей дают одну и ту же строку init
		h := fnv.New32a()
		h.Write([]byte(name + "|" + one))
		derived := fmt.Sprintf("f2n_tls_%08x", h.Sum32())
		m.inits = append(m.inits, derived+"=tls_mod("+name+",'"+one+"')")
		return derived, rt
	}

	fakesOf := func(kind string) []flowseal.Fake {
		var out []flowseal.Fake
		for _, f := range p.Fakes {
			if f.Kind == kind {
				out = append(out, f)
			}
		}
		return out
	}
	kinds := visibleKinds(p)

	// без своего TLS-фейка winws берёт встроенный с модами по умолчанию (rnd,rndsni,dupsid)
	// или с последним --dpi-desync-fake-tls-mod профиля
	defaultTLSMod := "rnd,rndsni,dupsid"
	if p.TLSModSet {
		defaultTLSMod = p.TLSMod
	}

	emitFakes := func(knownOnly bool) {
		for _, k := range kinds {
			if knownOnly && (k == "unknown" || k == "unknownudp") {
				continue
			}
			defs := fakesOf(k)
			if len(defs) == 0 {
				defs = []flowseal.Fake{{Kind: k, File: defaultFake[k].name, Mod: defaultTLSMod}}
			}
			for _, f := range defs {
				if f.File == "!" {
					f.File = defaultFake[k].name // "!" = встроенный ClientHello winws
				}
				if f.File == defaultFake[k].name {
					b.add(defaultFake[k].name, defaultFake[k].data())
				}
				name, rt := tlsRef(f)
				arg := []string{"blob=" + name}
				if rt != "" {
					arg = append(arg, "tls_mod="+rt)
				}
				arg = cat(arg, repeats, fooling, ipid)
				emit(fakePayload[k], "fake", arg...)
			}
		}
	}

	seqovl := func(markers bool) []string {
		if p.SeqOvl == "" {
			return nil
		}
		if markers || isDigits(p.SeqOvl) {
			return []string{"seqovl=" + p.SeqOvl}
		}
		warnf("split-seqovl=%s: для этого режима winws допускает только число — пропущен", p.SeqOvl)
		return nil
	}

	faked := func(fn string) {
		arg := []string{}
		if pos, approx := fakedPos(p.SplitPos); pos != "" {
			arg = append(arg, "pos="+pos)
			if approx {
				warnf("список позиций разреза свёрнут к одной (%s) — winws выбирал первую подходящую", pos)
			}
		}
		arg = append(arg, seqovl(fn == "fakeddisorder")...)
		arg = append(arg, blobArg("seqovl_pattern", p.SeqOvlPattern)...)
		arg = append(arg, blobArg("pattern", p.FakedsplitPattern)...)
		arg = append(arg, fakedsplitAlt(p.FakedsplitMod, warnf)...)
		arg = cat(arg, fooling, []string{"tcp_ts_up"}, ipid, repeats, []string{anyf})
		emit(base, fn, arg...)
	}

	for _, mode := range p.Desync {
		switch mode {
		case "syndata":
			// SYN — пустой пакет: фильтр payload не должен его отсекать
			emit("all", "syndata", cat(fooling, ipid)...)
		case "fake", "fakeknown":
			emitFakes(mode == "fakeknown")
		case "rst", "rstack":
			arg := cat(fooling, ipid, []string{anyf})
			if mode == "rstack" {
				arg = append(arg, "rstack")
			}
			emit(base, "rst", arg...)
		case "multisplit", "split2":
			arg := []string{}
			if pos := convPos(p.SplitPos); pos != "" {
				arg = append(arg, "pos="+pos)
			}
			arg = append(arg, seqovl(false)...)
			arg = append(arg, blobArg("seqovl_pattern", p.SeqOvlPattern)...)
			arg = cat(arg, ipid, []string{anyf})
			emit(base, "multisplit", arg...)
		case "multidisorder", "disorder2":
			arg := []string{}
			if pos := convPos(p.SplitPos); pos != "" {
				arg = append(arg, "pos="+pos)
			}
			arg = append(arg, seqovl(true)...)
			arg = append(arg, blobArg("seqovl_pattern", p.SeqOvlPattern)...)
			arg = cat(arg, ipid, []string{anyf})
			emit(base, "multidisorder", arg...)
		case "split", "fakedsplit":
			faked("fakedsplit")
		case "disorder", "fakeddisorder":
			faked("fakeddisorder")
		case "hostfakesplit":
			fn := "hostfakesplit"
			arg := []string{}
			for _, x := range splitCSV(p.HostfakesplitMod) {
				switch {
				case x == "" || x == "none", x == "altorder=0":
				case strings.HasPrefix(x, "host="):
					arg = append(arg, x)
				case x == "altorder=1":
					fn, m.alt = "f2n_hfs_alt", true
				default:
					warnf("hostfakesplit-mod=%s не имеет аналога в nfqws2 — пропущен", x)
				}
			}
			if p.HostfakesplitMidhost != "" {
				arg = append(arg, "midhost="+p.HostfakesplitMidhost)
			}
			arg = cat(arg, fooling, []string{"tcp_ts_up"}, ipid, repeats, []string{anyf})
			emit(base, fn, arg...)
		case "ipfrag2":
			arg := []string{"ipfrag"}
			if p.IpfragPosTCP != "" {
				arg = append(arg, "ipfrag_pos_tcp="+p.IpfragPosTCP)
			}
			if p.IpfragPosUDP != "" {
				arg = append(arg, "ipfrag_pos_udp="+p.IpfragPosUDP)
			}
			emit(base, "send", append(arg, anyf)...)
			emit(base, "drop", anyf)
		case "udplen":
			inc := p.UdplenIncrement
			if inc == "" {
				inc = "1"
			}
			arg := append([]string{"increment=" + inc}, blobArg("pattern", p.UdplenPattern)...)
			emit(base, "udplen", append(arg, anyf)...)
		default:
			warnf("mode=%s не поддерживается конвертером — пропущен", mode)
		}
	}
	return m
}

func cat(parts ...[]string) []string {
	var out []string
	for _, p := range parts {
		for _, v := range p {
			if v != "" {
				out = append(out, v)
			}
		}
	}
	return out
}

func luaJoin(base string, parts ...string) string {
	out := []string{base}
	for _, x := range parts {
		if x != "" {
			out = append(out, x)
		}
	}
	return strings.Join(out, ":")
}

func splitCSV(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func isDigits(v string) bool {
	if v == "" {
		return false
	}
	for _, c := range v {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// numArg переводит 0x-инкременты winws в десятичное число со знаком.
func numArg(v string) string {
	if strings.HasPrefix(v, "0x") {
		if n, err := strconv.ParseInt(v[2:], 16, 64); err == nil {
			if n > 0x7FFFFFFF {
				n -= 0x100000000
			}
			return strconv.FormatInt(n, 10)
		}
	}
	return v
}

// foolingArgs: искажения, благодаря которым сервер отбрасывает фейк.
// Применяются только к фейкам — как и в winws.
func foolingArgs(p *flowseal.Profile, warnf warnFunc) []string {
	var out []string
	for _, f := range p.Fooling {
		switch f {
		case "none":
		case "ts":
			v := p.TsIncrement
			if v == "" {
				v = "-600000"
			}
			out = append(out, "tcp_ts="+numArg(v))
		case "badseq":
			v, a := p.BadseqIncrement, p.BadackIncrement
			if v == "" {
				v = "-10000"
			}
			if a == "" {
				a = "-66000"
			}
			out = append(out, "tcp_seq="+numArg(v), "tcp_ack="+numArg(a))
		case "md5sig":
			out = append(out, "tcp_md5")
		case "badsum":
			out = append(out, "badsum")
		case "datanoack":
			out = append(out, "tcp_flags_unset=ACK")
		case "hopbyhop":
			out = append(out, "ip6_hopbyhop")
		case "hopbyhop2":
			out = append(out, "ip6_hopbyhop2")
		case "destopt":
			out = append(out, "ip6_destopt")
		default:
			warnf("fooling=%s не имеет прямого аналога в nfqws2 — пропущен", f)
		}
	}
	if p.Ttl != "" {
		out = append(out, "ip_ttl="+p.Ttl)
	}
	if p.Ttl6 != "" {
		out = append(out, "ip6_ttl="+p.Ttl6)
	}
	if p.TCPFlagsSet != "" {
		out = append(out, "tcp_flags_set="+strings.ToUpper(p.TCPFlagsSet))
	}
	if p.TCPFlagsUnset != "" {
		out = append(out, "tcp_flags_unset="+strings.ToUpper(p.TCPFlagsUnset))
	}
	return out
}

func ipIDArgs(p *flowseal.Profile, warnf warnFunc) []string {
	switch p.IpID {
	case "", "seq": // режим nfqws2 по умолчанию
		return nil
	case "zero", "rnd":
		return []string{"ip_id=" + p.IpID}
	default:
		warnf("ip-id=%s не поддерживается — используется seq", p.IpID)
		return nil
	}
}

// rangeArg: --dpi-desync-start / --dpi-desync-cutoff → --out-range.
// start = "по номеру больше или равно N" (включающая граница),
// cutoff = "по номеру меньше N" (исключающая).
func rangeArg(p *flowseal.Profile, warnf warnFunc) string {
	limit := func(v string) (string, bool) {
		if len(v) < 2 || (v[0] != 'n' && v[0] != 'd' && v[0] != 's') || !isDigits(v[1:]) {
			return "", false
		}
		return v, true
	}
	var lo, hi string
	if p.DesyncStart != "" {
		if v, ok := limit(p.DesyncStart); ok {
			lo = v
		} else {
			warnf("dpi-desync-start=%s не поддерживается — пропущен", p.DesyncStart)
		}
	}
	if p.Cutoff != "" {
		if v, ok := limit(p.Cutoff); ok {
			hi = v
		} else {
			warnf("dpi-desync-cutoff=%s не поддерживается — пропущен", p.Cutoff)
		}
	}
	switch {
	case lo != "" && hi != "" && lo[0] == hi[0]:
		return lo + "-<" + hi
	case lo != "" && hi != "":
		warnf("start и cutoff в разных режимах счётчика — применён только cutoff")
		return "<" + hi
	case lo != "":
		return lo + "-"
	case hi != "":
		return "<" + hi
	}
	return ""
}

// convPos: числовые позиции разреза winws сдвигаются на 1 (см. mapProfile),
// маркеры и отрицательные позиции остаются как есть.
func convPos(list string) string {
	var out []string
	for _, mk := range splitCSV(list) {
		if n, err := strconv.Atoi(mk); err == nil && n > 0 {
			mk = strconv.Itoa(n + 1)
		}
		out = append(out, mk)
	}
	return strings.Join(out, ",")
}

// fakedPos: fakedsplit/fakeddisorder режут по одной позиции.
func fakedPos(list string) (string, bool) {
	ms := splitCSV(list)
	if len(ms) < 2 {
		return convPos(list), false
	}
	for _, x := range ms {
		if _, err := strconv.Atoi(x); err != nil {
			return x, true
		}
	}
	return convPos(ms[0]), true
}

// splitTLSMod делит --dpi-desync-fake-tls-mod на однократные (при старте)
// и повторяющиеся (на каждый запрос) моды.
func splitTLSMod(mod string, warnf warnFunc) (string, string) {
	var sni, rndsni, rt []string
	for _, x := range splitCSV(mod) {
		switch {
		case x == "" || x == "none":
		case x == "rndsni":
			rndsni = append(rndsni, x)
		case strings.HasPrefix(x, "sni=") && safeLuaString(x):
			sni = append(sni, x)
		case x == "rnd" || x == "dupsid" || x == "padencap":
			rt = append(rt, x)
		default:
			warnf("fake-tls-mod=%s не поддерживается — пропущен", x)
		}
	}
	return strings.Join(append(sni, rndsni...), ","), strings.Join(rt, ",")
}

// safeLuaString: значение уйдёт в lua-строку в одинарных кавычках внутри конфига
func safeLuaString(v string) bool {
	return !strings.ContainsAny(v, "'\"`$\\ \t")
}

func fakedsplitAlt(mod string, warnf warnFunc) []string {
	var out []string
	for _, x := range splitCSV(mod) {
		if x == "" || x == "none" {
			continue
		}
		if !strings.HasPrefix(x, "altorder=") {
			warnf("fakedsplit-mod=%s не поддерживается — пропущен", x)
			continue
		}
		n, err := strconv.Atoi(x[len("altorder="):])
		if err != nil || n < 0 || n > 19 {
			warnf("fakedsplit-mod=%s не поддерживается — пропущен", x)
			continue
		}
		switch n % 8 {
		case 1:
			out = append(out, "nofake1")
		case 2:
			out = append(out, "nofake1", "nofake2")
		case 3:
			out = append(out, "nofake1", "nofake2", "nofake4")
		}
		if n >= 8 {
			warnf("fakedsplit-mod=%s: вариант для пакетов без позиции разреза в nfqws2 не воспроизводится", x)
		}
	}
	return out
}

// visibleKinds: протоколы, которые профиль вообще может увидеть.
// winws выбирает фейк по протоколу пакета, поэтому для каждого такого протокола
// нужен свой фейк (свой или встроенный).
func visibleKinds(p *flowseal.Profile) []string {
	tcp := len(p.FilterTCP) > 0 || len(p.FilterUDP) == 0
	udp := len(p.FilterUDP) > 0 || len(p.FilterTCP) == 0
	if len(p.FilterL7) > 0 {
		var ks []string
		for _, l7 := range p.FilterL7 {
			switch {
			case l7 == "unknown":
				if udp {
					ks = append(ks, "unknownudp")
				} else if tcp {
					ks = append(ks, "unknown")
				}
			case l7ToKind[l7] != "":
				ks = append(ks, l7ToKind[l7])
			}
		}
		return ks
	}
	var ks []string
	if tcp {
		ks = append(ks, "tls", "http")
		if p.AnyProtocol {
			ks = append(ks, "unknown")
		}
	}
	if udp {
		ks = append(ks, "quic", "discord", "stun", "wireguard", "dht")
		if p.AnyProtocol {
			ks = append(ks, "unknownudp")
		}
	}
	return ks
}

// routerLists holds canonical nfqws2 list paths.
type routerLists struct {
	User, Exclude, Ipset, IpsetExclude string
}

func defaultRouterLists() routerLists {
	return routerLists{
		User:         "/opt/etc/nfqws2/lists/user.list",
		Exclude:      "/opt/etc/nfqws2/lists/exclude.list",
		Ipset:        "/opt/etc/nfqws2/lists/ipset.list",
		IpsetExclude: "/opt/etc/nfqws2/lists/ipset_exclude.list",
	}
}

// domainListFromFile reads a flowseal list file into normalized domains.
func domainListFromFile(flowsealDir, file string) ([]string, error) {
	p := file
	if !filepath.IsAbs(p) {
		p = filepath.Join(flowsealDir, file)
	}
	if _, err := os.Stat(p); err != nil {
		p2 := filepath.Join(flowsealDir, "lists", filepath.Base(file))
		if _, err2 := os.Stat(p2); err2 == nil {
			p = p2
		} else {
			return nil, fmt.Errorf("list file not found: %s", file)
		}
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, ln := range strings.Split(string(data), "\n") {
		ln = strings.TrimSpace(strings.ReplaceAll(ln, "\r", ""))
		if ln == "" || strings.HasPrefix(ln, "#") || strings.HasPrefix(ln, "//") {
			continue
		}
		out = append(out, strings.ToLower(ln))
	}
	return out, nil
}
