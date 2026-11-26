// Package flowseal parses Flowseal zapret-discord-youtube .bat profiles
// (winws.exe command lines) into an intermediate representation.
package flowseal

import (
	"fmt"
	"os"
	"strings"
)

// Fake is one --dpi-desync-fake-* source.
type Fake struct {
	Kind string // tls, http, quic, unknown, unknownudp, discord, stun, wireguard, dht
	File string // path as written in the bat (flowseal-relative); "!" = winws built-in default
	Mod  string // --dpi-desync-fake-tls-mod in effect for this fake ("" = none)
}

// Profile is one winws profile (args between --new separators).
type Profile struct {
	Index                  int
	WfTCP                  []string // raw values from --wf-tcp (global, but kept per profile)
	WfUDP                  []string
	FilterTCP              []string
	FilterUDP              []string
	FilterL7               []string
	FilterL3               string
	HostlistFiles          []string
	HostlistDomains        []string
	HostlistExclude        []string
	HostlistExcludeDomains []string
	IpsetFiles             []string
	IpsetExcludeFiles      []string
	Desync                 []string
	Repeats                string
	Fooling                []string
	BadseqIncrement        string
	BadackIncrement        string
	Cutoff                 string
	DesyncStart            string
	AnyProtocol            bool
	Fakes                  []Fake
	TLSMod                 string // last --dpi-desync-fake-tls-mod seen in the profile
	TLSModSet              bool   // the profile had --dpi-desync-fake-tls-mod at all
	SplitPos               string
	SeqOvl                 string
	SeqOvlPattern          string
	FakedsplitPattern      string
	FakedsplitMod          string
	HostfakesplitMod       string
	HostfakesplitMidhost   string
	IpID                   string
	TsIncrement            string
	Ttl, Ttl6              string
	TCPFlagsSet            string
	TCPFlagsUnset          string
	IpfragPosTCP           string
	IpfragPosUDP           string
	UdplenIncrement        string
	UdplenPattern          string
	GamePorts              bool // ports referenced %GameFilter%
	Unknown                []string
}

// Parsed is the whole bat file.
type Parsed struct {
	Profiles []Profile
	WfTCP    []string // aggregated global Windows filter ports
	WfUDP    []string
	GameUsed bool // %GameFilter% vars are present in the bat
}

var fakeArgKind = map[string]string{
	"dpi-desync-fake-tls":         "tls",
	"dpi-desync-fake-http":        "http",
	"dpi-desync-fake-quic":        "quic",
	"dpi-desync-fake-unknown":     "unknown",
	"dpi-desync-fake-unknown-udp": "unknownudp",
	"dpi-desync-fake-discord":     "discord",
	"dpi-desync-fake-stun":        "stun",
	"dpi-desync-fake-wireguard":   "wireguard",
	"dpi-desync-fake-dht":         "dht",
}

func ParseBat(path string, gameTCP, gameUDP string) (*Parsed, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	lines := strings.Split(text, "\n")

	start := -1
	for i, ln := range lines {
		if strings.Contains(strings.ToLower(ln), "winws.exe") {
			start = i
			break
		}
	}
	if start < 0 {
		return nil, fmt.Errorf("%s: winws.exe not found", path)
	}

	ln := lines[start]
	k := strings.Index(strings.ToLower(ln), "winws.exe")
	rest := strings.TrimSpace(ln[k+len("winws.exe"):])
	rest = strings.TrimPrefix(rest, "\"")
	rest = strings.TrimSpace(rest)
	// join continuations; the last continuation line has no trailing ^
	var cmd string
	if strings.HasSuffix(rest, "^") {
		cmd = strings.TrimSpace(strings.TrimSuffix(rest, "^"))
		for i := start + 1; i < len(lines); i++ {
			t := strings.TrimSpace(lines[i])
			if strings.HasSuffix(t, "^") {
				cmd += " " + strings.TrimSuffix(t, "^")
			} else {
				cmd += " " + t
				break
			}
		}
	} else {
		cmd = rest
	}

	toks := tokenize(cmd)
	p := &Parsed{}
	var cur []string
	flush := func() {
		if len(cur) == 0 {
			return
		}
		if prof := parseProfile(cur, gameTCP, gameUDP); prof != nil {
			prof.Index = len(p.Profiles) + 1
			p.Profiles = append(p.Profiles, *prof)
		}
		cur = nil
	}
	for _, tok := range toks {
		if tok == "--new" {
			flush()
			continue
		}
		cur = append(cur, tok)
	}
	flush()

	// aggregate global Windows filter ports
	for i := range p.Profiles {
		for _, v := range p.Profiles[i].WfTCP {
			p.WfTCP = addPorts(p.WfTCP, v)
		}
		for _, v := range p.Profiles[i].WfUDP {
			p.WfUDP = addPorts(p.WfUDP, v)
		}
		if p.Profiles[i].GamePorts {
			p.GameUsed = true
		}
	}
	return p, nil
}

// parseProfile converts tokens of one profile into a Profile.
// Returns nil for profiles without a desync strategy (with no way to report here).
func parseProfile(toks []string, gameTCP, gameUDP string) *Profile {
	pr := &Profile{}
	hasDesync := false
	// winws: a fake takes the tls-mod that is in effect at its definition;
	// a later --dpi-desync-fake-tls-mod overrides the mod of the last TLS fake
	curTLSMod := ""
	setTLSMod := func(val string) {
		curTLSMod = val
		pr.TLSMod, pr.TLSModSet = val, true
		for i := len(pr.Fakes) - 1; i >= 0; i-- {
			if pr.Fakes[i].Kind == "tls" {
				pr.Fakes[i].Mod = val
				break
			}
		}
	}
	for _, tok := range toks {
		isGame := strings.Contains(tok, "%GameFilter")
		tok = expandVars(tok, gameTCP, gameUDP)
		if tok == "" {
			continue
		}
		name, val := splitArg(tok)
		switch name {
		case "wf-tcp":
			if val != "" {
				pr.WfTCP = append(pr.WfTCP, val)
			}
		case "wf-udp":
			if val != "" {
				pr.WfUDP = append(pr.WfUDP, val)
			}
		case "filter-tcp":
			if isGame && val == "" {
				pr.GamePorts = true // ports came solely from %GameFilterTCP%
			}
			pr.FilterTCP = append(pr.FilterTCP, splitList(val)...)
		case "filter-udp":
			if isGame && val == "" {
				pr.GamePorts = true
			}
			pr.FilterUDP = append(pr.FilterUDP, splitList(val)...)
		case "filter-l7":
			pr.FilterL7 = append(pr.FilterL7, splitList(val)...)
		case "hostlist":
			pr.HostlistFiles = append(pr.HostlistFiles, val)
		case "hostlist-domains":
			pr.HostlistDomains = append(pr.HostlistDomains, splitList(val)...)
		case "hostlist-exclude":
			pr.HostlistExclude = append(pr.HostlistExclude, val)
		case "hostlist-exclude-domains":
			pr.HostlistExcludeDomains = append(pr.HostlistExcludeDomains, splitList(val)...)
		case "filter-l3":
			pr.FilterL3 = val
		case "ipset":
			pr.IpsetFiles = append(pr.IpsetFiles, val)
		case "ipset-exclude":
			pr.IpsetExcludeFiles = append(pr.IpsetExcludeFiles, val)
		case "dpi-desync":
			pr.Desync = append(pr.Desync, splitList(val)...)
			hasDesync = true
		case "dpi-desync-repeats":
			pr.Repeats = val
		case "dpi-desync-fooling":
			pr.Fooling = append(pr.Fooling, splitList(val)...)
		case "dpi-desync-cutoff":
			pr.Cutoff = val
		case "dpi-desync-start":
			pr.DesyncStart = val
		case "dpi-desync-ts-increment":
			pr.TsIncrement = val
		case "dpi-desync-badseq-increment":
			pr.BadseqIncrement = val
		case "dpi-desync-badack-increment":
			pr.BadackIncrement = val
		case "dpi-desync-split-pos":
			pr.SplitPos = val
		case "dpi-desync-split-seqovl":
			pr.SeqOvl = val
		case "dpi-desync-split-seqovl-pattern":
			pr.SeqOvlPattern = val
		case "dpi-desync-any-protocol":
			pr.AnyProtocol = true
		case "ip-id":
			pr.IpID = val
		case "dpi-desync-fake-tls-mod":
			setTLSMod(val)
		case "dpi-desync-hostfakesplit-mod":
			pr.HostfakesplitMod = val
		case "dpi-desync-hostfakesplit-midhost":
			pr.HostfakesplitMidhost = val
		case "dpi-desync-fakedsplit-pattern":
			pr.FakedsplitPattern = val
		case "dpi-desync-fakedsplit-mod":
			pr.FakedsplitMod = val
		case "dpi-desync-ttl":
			pr.Ttl = val
		case "dpi-desync-ttl6":
			pr.Ttl6 = val
		case "dpi-desync-tcp-flags-set":
			pr.TCPFlagsSet = val
		case "dpi-desync-tcp-flags-unset":
			pr.TCPFlagsUnset = val
		case "dpi-desync-ipfrag-pos-tcp":
			pr.IpfragPosTCP = val
		case "dpi-desync-ipfrag-pos-udp":
			pr.IpfragPosUDP = val
		case "dpi-desync-udplen-increment":
			pr.UdplenIncrement = val
		case "dpi-desync-udplen-pattern":
			pr.UdplenPattern = val
		default:
			if kind, ok := fakeArgKind[name]; ok {
				f := Fake{Kind: kind, File: normalizeFakeRef(val)}
				if kind == "tls" {
					f.Mod = curTLSMod
				}
				pr.Fakes = append(pr.Fakes, f)
				hasDesync = true
			} else {
				pr.Unknown = append(pr.Unknown, tok)
			}
		}
	}
	if !hasDesync {
		return nil
	}
	return pr
}

// normalizeFakeRef turns the batch-escaped winws fake reference into a plain one:
// "^!" → "!", "@file" → "file", "!+ofs" → "!" (offsets are not used by Flowseal).
func normalizeFakeRef(val string) string {
	if val == "" {
		return ""
	}
	val = strings.TrimPrefix(val, "^") // бат-экранирование: "^!" → "!"
	if val == "" {
		return ""
	}
	if val[0] == '!' {
		return "!"
	}
	return strings.TrimPrefix(val, "@")
}

func expandVars(tok, gameTCP, gameUDP string) string {
	r := strings.NewReplacer(
		"%BIN%", "", "%LISTS%", "", "%~dp0%", "",
		"%GameFilterTCP%", gameTCP, "%GameFilterUDP%", gameUDP,
	)
	out := r.Replace(tok)
	out = strings.Trim(out, "\"")
	return out
}

func firstN(toks []string, n int) string {
	if len(toks) > n {
		toks = toks[:n]
	}
	return strings.Join(toks, " ")
}

func splitArg(tok string) (name, val string) {
	tok = strings.TrimPrefix(tok, "--")
	if i := strings.Index(tok, "="); i >= 0 {
		return tok[:i], tok[i+1:]
	}
	return tok, ""
}

func splitList(val string) []string {
	var out []string
	for _, s := range strings.Split(val, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func addPorts(dst []string, val string) []string {
	for _, s := range splitList(val) {
		s = strings.ReplaceAll(s, "-", ":")
		dup := false
		for _, e := range dst {
			if e == s {
				dup = true
				break
			}
		}
		if !dup {
			dst = append(dst, s)
		}
	}
	return dst
}

func tokenize(s string) []string {
	var toks []string
	var cur strings.Builder
	inQuote := false
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
		case (r == ' ' || r == '\t') && !inQuote:
			if t := cur.String(); t != "" && t != "^" {
				toks = append(toks, t)
			}
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if t := cur.String(); t != "" && t != "^" {
		toks = append(toks, t)
	}
	return toks
}
