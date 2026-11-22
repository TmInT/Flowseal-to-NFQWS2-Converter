package convert

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"f2n/internal/flowseal"
)

// fakePayload maps winws fake-source kind to nfqws2 payload name.
var fakePayload = map[string]string{
	"tls":        "tls_client_hello",
	"http":       "http_req",
	"quic":       "quic_initial",
	"unknown":    "unknown",
	"unknownudp": "unknown",
	"discord":    "discord_ip_discovery",
	"stun":       "stun",
}

// blobStore collects and names blobs from the Flowseal folder.
type blobStore struct {
	dir   string
	names map[string]string // source abs path -> blob name
	order []string
	files map[string]string // blob name -> source abs path
}

func newBlobStore(binDir string) *blobStore {
	return &blobStore{dir: binDir, names: map[string]string{}, files: map[string]string{}}
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
	base := strings.ToLower(strings.TrimSuffix(filepath.Base(src), filepath.Ext(src)))
	for i := 2; ; i++ {
		if _, exists := b.files[base]; !exists {
			break
		}
		base = fmt.Sprintf("%s_%d", base, i)
	}
	b.names[abs] = base
	b.files[base] = abs
	b.order = append(b.order, base)
	return base, nil
}

// profArgs accumulates nfqws2 args for one profile.
type profArgs struct {
	args []string
	core []string // strategy args without filter/list args (for ipset folding)
}

func (a *profArgs) block(payload, lua string) {
	a.args = append(a.args, "--payload="+payload, "--lua-desync="+lua)
	a.core = append(a.core, lua)
}

// mapProfile converts one winws profile into nfqws2 args.
func mapProfile(p *flowseal.Profile, blobs *blobStore) (out profArgs, warns []string) {
	tsVal := func() string {
		if p.TsIncrement != "" {
			return p.TsIncrement
		}
		return "-600000" // convention used by working nfqws2 configs
	}

	luaJoin := func(base string, parts ...string) string {
		out := []string{base}
		for _, x := range parts {
			if x != "" {
				out = append(out, x)
			}
		}
		return strings.Join(out, ":")
	}

	foolingParts := func() (out []string) {
		for _, f := range p.Fooling {
			switch f {
			case "ts":
				out = append(out, "tcp_ts="+tsVal())
			case "badseq":
				if p.BadseqIncrement != "" {
					out = append(out, "tcp_seq="+p.BadseqIncrement)
				} else {
					out = append(out, "tcp_seq=-10000", "tcp_ack=-66000")
				}
			case "md5sig":
				out = append(out, "tcp_md5")
			case "badsum":
				out = append(out, "badsum")
			default:
				warns = append(warns, fmt.Sprintf("fooling=%s не имеет прямого аналога в nfqws2 — пропущен", f))
			}
		}
		return out
	}
	ipID := func() string {
		if p.IpID == "zero" {
			return "ip_id=zero"
		}
		return ""
	}
	repeats := func() string {
		if p.Repeats == "" {
			return ""
		}
		return "repeats=" + p.Repeats
	}
	pos := func() string {
		if p.SplitPos == "" {
			return ""
		}
		return "pos=" + p.SplitPos
	}
	seqovl := func() string {
		if p.SeqOvl == "" {
			return ""
		}
		return "seqovl=" + p.SeqOvl
	}
	payloadUnion := func() string {
		if p.AnyProtocol {
			return "all"
		}
		seen := map[string]bool{}
		var out []string
		for _, f := range p.Fakes {
			n := fakePayload[f.Kind]
			if !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
		if len(out) == 0 {
			warns = append(warns, "у профиля нет fake-файлов — payload по умолчанию tls_client_hello")
			out = []string{"tls_client_hello"}
		}
		return strings.Join(out, ",")
	}
	blob := func(file string) string {
		if file == "!" || file == "^!" {
			warns = append(warns, "fake-источник \"!\" (заглушка Flowseal) — пропущен")
			return ""
		}
		if strings.HasPrefix(file, "0x") {
			return file // inline hex blob, nfqws2 понимает напрямую
		}
		n, err := blobs.blobName(file)
		if err != nil {
			warns = append(warns, err.Error()+" — использован blob=0x00000000")
			return "0x00000000"
		}
		return n
	}
	pattern := func(file string) string {
		if file == "" {
			return ""
		}
		n, err := blobs.blobName(file)
		if err != nil {
			warns = append(warns, "seqovl_pattern: "+err.Error()+" — параметр опущен")
			return ""
		}
		return "seqovl_pattern=" + n
	}
	// patternOrHex: nfqws1 разрешает паттерн как файл, так и 0x-hex
	patternOrHex := func(file, hex string) string {
		if hex != "" {
			if strings.HasPrefix(hex, "0x") {
				return "seqovl_pattern=" + hex
			}
			warns = append(warns, "pattern="+hex+" — не 0x-hex и не файл, пропущен")
			return ""
		}
		return pattern(file)
	}

	fakeArgs := func(blobName, tlsMod string) string {
		parts := []string{"fake:blob=" + blobName}
		if r := repeats(); r != "" {
			parts = append(parts, r)
		}
		if tlsMod != "" && tlsMod != "none" {
			parts = append(parts, "tls_mod="+tlsMod)
		}
		parts = append(parts, foolingParts()...)
		if v := ipID(); v != "" {
			parts = append(parts, v)
		}
		return strings.Join(parts, ":")
	}

	for _, mode := range p.Desync {
		switch mode {
		case "fake":
			if len(p.Fakes) == 0 {
				warns = append(warns, "mode=fake без fake-файлов — использован blob=0x00000000")
				out.block("unknown", fakeArgs("0x00000000", ""))
				continue
			}
			for _, f := range p.Fakes {
				bn := blob(f.File)
				if bn == "" {
					continue
				}
				out.block(fakePayload[f.Kind], fakeArgs(bn, f.Mod))
			}
		case "syndata":
			// zapret2: нативная lua-функция syndata (нулевая фаза, SYN с payload)
			out.block(payloadUnion(), luaJoin("syndata", foolingParts()...))
			warns = append(warns, "syndata — нулевая фаза; в nfqws2 работает с хостлистами только в режиме --ipcache-hostname")
		case "multisplit", "split2", "split":
			if mode != "multisplit" {
				warns = append(warns, fmt.Sprintf("mode=%s заменён на multisplit (nfqws2-эквивалент)", mode))
			}
			out.block(payloadUnion(), luaJoin("multisplit", pos(), seqovl(), pattern(p.SeqOvlPattern), ipID()))
		case "disorder", "disorder2", "multidisorder":
			if mode != "multidisorder" {
				warns = append(warns, fmt.Sprintf("mode=%s заменён на multidisorder", mode))
			}
			out.block(payloadUnion(), luaJoin("multidisorder", pos()))
		case "fakedsplit":
			out.block(payloadUnion(), luaJoin("fakedsplit",
				pos(), seqovl(), patternOrHex(p.SeqOvlPattern, p.FakedsplitPattern), "tcp_seq=-10000", ipID()))
		case "fakeddisorder":
			out.block(payloadUnion(), luaJoin("fakeddisorder",
				pos(), patternOrHex(p.SeqOvlPattern, p.FakedsplitPattern), "tcp_seq=-10000", ipID()))
		case "hostfakesplit":
			var hf []string
			altorder := false
			for _, m := range strings.Split(p.HostfakesplitMod, ",") {
				m = strings.TrimSpace(m)
				switch {
				case m == "":
				case strings.HasPrefix(m, "host="):
					hf = append(hf, m)
				case strings.HasPrefix(m, "altorder="):
					altorder = true
				default:
					warns = append(warns, fmt.Sprintf("hostfakesplit-mod=%s — нет аналога в nfqws2, пропущен", m))
				}
			}
			if altorder {
				warns = append(warns, "hostfakesplit altorder=1 не имеет точного эквивалента в nfqws2 — порядок сегментов будет стандартным (приближение)")
			}
			parts := append([]string{}, hf...)
			parts = append(parts, seqovl(), pattern(p.SeqOvlPattern))
			parts = append(parts, foolingParts()...)
			if v := ipID(); v != "" {
				parts = append(parts, v)
			}
			out.block(payloadUnion(), luaJoin("hostfakesplit", parts...))
		default:
			warns = append(warns, fmt.Sprintf("mode=%s не поддерживается конвертером — пропущен", mode))
		}
	}

	// cutoff → out-range (stock nfqws2 syntax: --out-range=<nN)
	if p.Cutoff != "" {
		out.args = append(out.args, "--out-range=<"+p.Cutoff)
	}

	// filter-l3 (встречается в EXP): L3-ограничение в nfqws2 делается через IPV6_ENABLED
	if p.FilterL3 == "ipv4" {
		warns = append(warns, "профиль ограничен IPv4 (filter-l3=ipv4) — при необходимости задайте IPV6_ENABLED=0 вручную")
	} else if p.FilterL3 != "" {
		warns = append(warns, "filter-l3="+p.FilterL3+" не поддерживается — пропущен")
	}
	return out, warns
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
