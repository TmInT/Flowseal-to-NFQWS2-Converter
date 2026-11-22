package convert

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"f2n/internal/flowseal"
)

// Options configures one conversion run.
type Options struct {
	FlowsealDir string // zapret-discord-youtube root (contains bin\ and lists\)
	BatFile     string // path to the .bat profile
	OutputDir   string
	Interface   string
	Policy      string
	GameFilter  string // disabled|tcp|udp|all
	Strict      bool
	DryRun      bool
}

// Result of a conversion.
type Result struct {
	Conf      string
	SlotTable []string
	Warnings  []string
	Infos     []string
}

// toolVersion — версия инструмента для заголовка конфига и REPORT.md.
// В релизной сборке GitHub Actions подменяет её по git-тегу:
// -ldflags "-X 'f2n/internal/convert.toolVersion=F2N v1.1.x'".
var toolVersion = "F2N v1.1.2"

// Version возвращает версию инструмента (для отображения в GUI).
func Version() string { return toolVersion }

type slotProf struct {
	p      *flowseal.Profile
	mapped profArgs
	kind   string
}

// Run performs the whole conversion.
func Run(opts Options) (*Result, error) {
	res := &Result{}
	rl := defaultRouterLists()

	gameTCP, gameUDP := "", ""
	switch opts.GameFilter {
	case "tcp", "all":
		gameTCP = "1024-65535"
	}
	switch opts.GameFilter {
	case "udp", "all":
		gameUDP = "1024-65535"
	}
	if opts.GameFilter != "disabled" {
		res.Infos = append(res.Infos, "Game Filter включён ("+opts.GameFilter+") — порты 1024-65535 добавлены в очереди и стратегии")
	}

	parsed, err := flowseal.ParseBat(opts.BatFile, gameTCP, gameUDP)
	if err != nil {
		return nil, err
	}

	slots := make([]slotProf, len(parsed.Profiles))
	for i := range parsed.Profiles {
		slots[i].p = &parsed.Profiles[i]
	}

	hasDomainList := func(p *flowseal.Profile) bool {
		return len(p.HostlistFiles) > 0 || len(p.HostlistDomains) > 0
	}
	isIpset := func(p *flowseal.Profile) bool {
		return len(p.IpsetFiles) > 0
	}
	hasPort := func(list []string, port string) bool {
		for _, v := range list {
			if v == port {
				return true
			}
		}
		return false
	}

	// ---- pass 1: structural classification (no mapping yet) ----
	var quicMain, tcpMain, udpMain *slotProf
	for i := range slots {
		sp := &slots[i]
		p := sp.p
		switch {
		case p.GamePorts && opts.GameFilter == "disabled":
			sp.kind = "dropped"
		case isIpset(p) && !hasDomainList(p):
			sp.kind = "ipset-cand"
		case hasPort(p.FilterUDP, "443") && hasDomainList(p):
			sp.kind = "quic-main"
			quicMain = sp // last wins
		case hasPort(p.FilterTCP, "443") && hasDomainList(p):
			sp.kind = "tcp-main"
			tcpMain = sp // last wins
		case len(p.FilterUDP) > 0:
			if udpMain == nil {
				sp.kind = "udp-main"
				udpMain = sp
			} else {
				sp.kind = "custom"
			}
		default:
			sp.kind = "custom"
		}
	}

	// ---- pass 2: demote non-last mains ----
	for i := range slots {
		sp := &slots[i]
		switch sp.kind {
		case "quic-main":
			if sp != quicMain {
				sp.kind = "custom"
				res.Warnings = append(res.Warnings, fmt.Sprintf("профиль %d: несколько общих QUIC-профилей — не последний перенесён в CUSTOM", sp.p.Index))
			}
		case "tcp-main":
			if sp != tcpMain {
				sp.kind = "custom"
				res.Warnings = append(res.Warnings, fmt.Sprintf("профиль %d: несколько общих TCP-профилей — не последний перенесён в CUSTOM с инлайн-доменами", sp.p.Index))
			}
		}
	}

	// ---- pass 3: map surviving profiles (blobs only for them) ----
	blobs := newBlobStore(filepath.Join(opts.FlowsealDir, "bin"))
	for i := range slots {
		sp := &slots[i]
		if sp.kind == "dropped" {
			continue
		}
		m, w := mapProfile(sp.p, blobs)
		for _, x := range w {
			res.Warnings = append(res.Warnings, fmt.Sprintf("профиль %d: %s", sp.p.Index, x))
		}
		sp.mapped = m
	}
	// ---- pass 4: fold ipset candidates whose strategy equals a main slot ----
	coreEq := func(a, b []string) bool {
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}
	ipsetFold := false
	for i := range slots {
		sp := &slots[i]
		if sp.kind != "ipset-cand" {
			continue
		}
		switch {
		case quicMain != nil && hasPort(sp.p.FilterUDP, "443") && coreEq(sp.mapped.core, quicMain.mapped.core):
			ipsetFold = true
			sp.kind = "ipset-folded-quic"
		case tcpMain != nil && hasPort(sp.p.FilterTCP, "443") && coreEq(sp.mapped.core, tcpMain.mapped.core):
			ipsetFold = true
			sp.kind = "ipset-folded-tcp"
		default:
			sp.kind = "custom"
		}
	}

	if tcpMain == nil {
		res.Warnings = append(res.Warnings, "в пресете нет общего TCP-профиля — NFQWS_ARGS пуст, спискам MODE_AUTO не к чему применяться")
	}
	if quicMain == nil {
		res.Infos = append(res.Infos, "в пресете нет общего QUIC-профиля — NFQWS_ARGS_QUIC пуст")
	}

	filterArgs := func(p *flowseal.Profile) []string {
		var out []string
		if len(p.FilterTCP) > 0 {
			out = append(out, "--filter-tcp="+strings.Join(p.FilterTCP, ","))
		}
		if len(p.FilterUDP) > 0 {
			out = append(out, "--filter-udp="+strings.Join(p.FilterUDP, ","))
		}
		if len(p.FilterL7) > 0 {
			out = append(out, "--filter-l7="+strings.Join(p.FilterL7, ","))
		}
		return out
	}

	// rewrite list args of custom profiles into NFQWS2-native forms
	listArgs := func(p *flowseal.Profile) ([]string, []string) {
		var out, w []string
		emit := func(a string) {
			for _, e := range out {
				if e == a {
					return // Flowseal повторяет один и тот же exclude дважды (.txt + .user)
				}
			}
			out = append(out, a)
		}
		for range p.IpsetFiles {
			emit("--ipset=" + rl.Ipset)
		}
		for range p.IpsetExcludeFiles {
			emit("--ipset-exclude=" + rl.IpsetExclude)
		}
		for _, f := range p.HostlistFiles {
			domains, err := domainListFromFile(opts.FlowsealDir, f)
			if err != nil {
				w = append(w, fmt.Sprintf("профиль %d: список %s не прочитан (%v) — аргумент пропущен", p.Index, filepath.Base(f), err))
				continue
			}
			if len(domains) == 0 {
				continue
			}
			out = append(out, "--hostlist-domains="+strings.Join(domains, ","))
		}
		for _, d := range p.HostlistDomains {
			emit("--hostlist-domains=" + d)
		}
		if len(p.HostlistExcludeDomains) > 0 {
			emit("--hostlist-exclude-domains=" + strings.Join(p.HostlistExcludeDomains, ","))
		}
		for range p.HostlistExclude {
			emit("--hostlist-exclude=" + rl.Exclude)
		}
		return out, w
	}

	// ---- build conf ----
	var conf strings.Builder
	fmt.Fprintf(&conf, "# Converted by %s from Flowseal profile: %s\n\n", toolVersion, filepath.Base(opts.BatFile))
	fmt.Fprintf(&conf, "ISP_INTERFACE='%s'\n\n", opts.Interface)

	var base []string
	base = append(base,
		"--fastpath-workaround=auto",
		"--lua-init=@/opt/etc/nfqws2/lua/zapret-lib.lua",
		"--lua-init=@/opt/etc/nfqws2/lua/zapret-antidpi.lua")
	// блобы инлайнятся hex'ом: конфиг самодостаточен и деплоится целиком
	// через файловый API веб-морды (blobs/ на роутере не требуются)
	for _, name := range blobs.order {
		data, err := os.ReadFile(blobs.files[name])
		if err != nil {
			return nil, fmt.Errorf("blob %s: %w", name, err)
		}
		base = append(base, fmt.Sprintf("--blob=%s:0x%x", name, data))
	}
	fmt.Fprintf(&conf, "NFQWS_BASE_ARGS=\"%s\"\n", indentLines(strings.Join(base, "\n")))

	emitSlot := func(label string, sp *slotProf) {
		v := ""
		if sp != nil {
			all := append(filterArgs(sp.p), sp.mapped.args...)
			v = strings.Join(all, "\n")
		}
		fmt.Fprintf(&conf, "%s=\"%s\"\n", label, indentLines(v))
	}
	emitSlot("NFQWS_ARGS", tcpMain)
	emitSlot("NFQWS_ARGS_QUIC", quicMain)
	emitSlot("NFQWS_ARGS_UDP", udpMain)

	conf.WriteString("# Режимы работы со списками доменов (workflow NFQWS2 — не изменять)\n")
	conf.WriteString("MODE_LIST=\"--hostlist=/opt/etc/nfqws2/lists/user.list\"\n\n")
	conf.WriteString("MODE_ALL=\"--hostlist-exclude=/opt/etc/nfqws2/lists/exclude.list\"\n\n")
	conf.WriteString("MODE_AUTO=\"$MODE_LIST --hostlist-auto=/opt/etc/nfqws2/lists/auto.list --hostlist-auto-debug=/opt/var/log/nfqws2.log $MODE_ALL\"\n\n")
	conf.WriteString("NFQWS_EXTRA_ARGS=\"$MODE_AUTO\"\n")

	if ipsetFold {
		fmt.Fprintf(&conf, "NFQWS_ARGS_IPSET=\"--ipset=%s --ipset-exclude=%s\"\n", rl.Ipset, rl.IpsetExclude)
	} else {
		conf.WriteString("NFQWS_ARGS_IPSET=\"\"\n")
	}

	var custLines []string
	for i := range slots {
		sp := &slots[i]
		if sp.kind != "custom" {
			continue
		}
		la, lw := listArgs(sp.p)
		res.Warnings = append(res.Warnings, lw...)
		line := append(filterArgs(sp.p), la...)
		line = append(line, sp.mapped.args...)
		if len(line) == 0 {
			continue
		}
		if len(custLines) > 0 {
			custLines = append(custLines, "--new")
		}
		custLines = append(custLines, strings.Join(line, "\n"))
	}
	if len(custLines) > 0 {
		fmt.Fprintf(&conf, "\nNFQWS_ARGS_CUSTOM=\"%s\"\n", indentLines(strings.Join(custLines, "\n")))
	} else {
		conf.WriteString("\nNFQWS_ARGS_CUSTOM=\"\"\n")
	}

	fmt.Fprintf(&conf, "\nIPV6_ENABLED=1\nTCP_PORTS=%s\nUDP_PORTS=%s\n\n", strings.Join(parsed.WfTCP, ","), strings.Join(parsed.WfUDP, ","))
	fmt.Fprintf(&conf, "POLICY_NAME='%s'\nPOLICY_EXCLUDE=0\n\n", opts.Policy)
	conf.WriteString("LOG_LEVEL=0\nLOG_DEBUG_PATH=\"\"\n\nNFQUEUE_NUM=300\nUSER=nobody\nCONFIG_VERSION=1\n")
	res.Conf = conf.String()

	// ---- slot table ----
	for i := range slots {
		sp := &slots[i]
		res.SlotTable = append(res.SlotTable, fmt.Sprintf("| %d | %s | %s |", sp.p.Index, describeProfile(sp.p), sp.kind))
	}
	return res, nil
}

func describeProfile(p *flowseal.Profile) string {
	var parts []string
	if len(p.FilterTCP) > 0 {
		parts = append(parts, "tcp="+strings.Join(p.FilterTCP, ","))
	}
	if len(p.FilterUDP) > 0 {
		parts = append(parts, "udp="+strings.Join(p.FilterUDP, ","))
	}
	if len(p.FilterL7) > 0 {
		parts = append(parts, "l7="+strings.Join(p.FilterL7, ","))
	}
	if len(p.Desync) > 0 {
		parts = append(parts, "desync="+strings.Join(p.Desync, "+"))
	}
	if p.GamePorts {
		parts = append(parts, "gamefilter")
	}
	return strings.Join(parts, " ")
}

func indentLines(s string) string {
	if s == "" {
		return s
	}
	lines := strings.Split(s, "\n")
	for i := 1; i < len(lines); i++ {
		lines[i] = "            " + lines[i]
	}
	return strings.Join(lines, "\n")
}

// ListAdditions reads Flowseal lists and builds delta files for the router lists.
func ListAdditions(flowsealDir string) (map[string][]string, []string) {
	warns := []string{}
	read := func(names ...string) []string {
		var out []string
		for _, n := range names {
			if d, err := domainListFromFile(flowsealDir, n); err == nil {
				out = append(out, d...)
			}
		}
		return sortStableUnique(out)
	}
	adds := map[string][]string{
		"user.list":          read("lists/list-general.txt", "lists/list-general-user.txt"),
		"exclude.list":       read("lists/list-exclude.txt", "lists/list-exclude-user.txt"),
		"ipset.list":         read("lists/ipset-all.txt", "lists/ipset-all-user.txt"),
		"ipset_exclude.list": read("lists/ipset-exclude.txt", "lists/ipset-exclude-user.txt"),
	}
	if len(adds["user.list"]) == 0 {
		warns = append(warns, "list-general.txt пуст или не найден — user.list.add без доменов")
	}
	return adds, warns
}

func sortStableUnique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// WriteOutputs writes the conversion result to the output directory.
func WriteOutputs(opts Options, res *Result) ([]string, error) {
	if err := os.MkdirAll(opts.OutputDir, 0o755); err != nil {
		return nil, err
	}
	var files []string
	confPath := filepath.Join(opts.OutputDir, "nfqws2.conf")
	if err := os.WriteFile(confPath, []byte(res.Conf), 0o644); err != nil {
		return nil, err
	}
	files = append(files, confPath)

	adds, lw := ListAdditions(opts.FlowsealDir)
	res.Warnings = append(res.Warnings, lw...)
	listsDir := filepath.Join(opts.OutputDir, "lists")
	if err := os.MkdirAll(listsDir, 0o755); err != nil {
		return nil, err
	}
	for name, lines := range adds {
		if len(lines) == 0 {
			continue
		}
		p := filepath.Join(listsDir, name+".add")
		if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
			return nil, err
		}
		files = append(files, p)
	}

	report := buildReport(opts, res)
	rp := filepath.Join(opts.OutputDir, "REPORT.md")
	if err := os.WriteFile(rp, []byte(report), 0o644); err != nil {
		return nil, err
	}
	files = append(files, rp)

	manifest := map[string]string{
		"tool":       toolVersion,
		"created":    time.Now().Format(time.RFC3339),
		"source_bat": opts.BatFile,
		"gameFilter": opts.GameFilter,
		"files":      strings.Join(files, ", "),
	}
	mj, _ := json.MarshalIndent(manifest, "", "  ")
	mp := filepath.Join(opts.OutputDir, "manifest.json")
	if err := os.WriteFile(mp, mj, 0o644); err != nil {
		return nil, err
	}
	files = append(files, mp)
	return files, nil
}

func buildReport(opts Options, res *Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Отчёт конвертации %s → nfqws2\n\n", filepath.Base(opts.BatFile))
	fmt.Fprintf(&b, "Инструмент: %s · Источник: `%s` · GameFilter: %s · Интерфейс: %s\n\n", toolVersion, opts.BatFile, opts.GameFilter, opts.Interface)

	b.WriteString("## Профили\n\n| # | Профиль | Слот |\n|---|---|---|\n")
	for _, l := range res.SlotTable {
		b.WriteString(l + "\n")
	}
	b.WriteString("\nСлоты: `NFQWS_ARGS` — главный TCP-профиль, наследует списки MODE_AUTO (user.list + auto.list + exclude.list); " +
		"`NFQWS_ARGS_QUIC` — главный QUIC-профиль (аналогично); `NFQWS_ARGS_UDP` — спец-UDP (без списков MODE); " +
		"`NFQWS_ARGS_CUSTOM` — спец-профили (инлайн-домены); `ipset-folded-*` — свернут в `NFQWS_ARGS_IPSET`; " +
		"`dropped` — пропущен (Game Filter выключен).\n\n")

	if len(res.Warnings) > 0 {
		b.WriteString("## Предупреждения\n\n")
		for _, w := range res.Warnings {
			b.WriteString("- ⚠ " + w + "\n")
		}
		b.WriteString("\n")
	}
	if len(res.Infos) > 0 {
		b.WriteString("## Заметки\n\n")
		for _, w := range res.Infos {
			b.WriteString("- ℹ " + w + "\n")
		}
		b.WriteString("\n")
	}

	b.WriteString(`## Установка

1. Бэкап текущего конфига роутера: ` + "`cp /opt/etc/nfqws2/nfqws2.conf /opt/etc/nfqws2/nfqws2.conf.bak`" + `
2. Скопируйте на роутер:
   - ` + "`nfqws2.conf`" + ` → ` + "`/opt/etc/nfqws2/nfqws2.conf`" + ` (блобы уже инлайн в конфиге — отдельные файлы не нужны)
   - списки: дополните ` + "`/opt/etc/nfqws2/lists/`" + ` строками из ` + "`lists/*.add`" + ` (user.list, exclude.list, ipset.list, ipset_exclude.list) — только те строки, которых ещё нет.
3. Перезапустите службу: веб-морда (кнопка с полосками → Restart) или ` + "`/opt/etc/init.d/S51nfqws2 restart`" + `.
4. Проверьте работу Discord/YouTube с клиента.

## Списки и автохостлист

Домены Flowseal слиты со штатными списками NFQWS2 (user.list / exclude.list / ipset.list / ipset_exclude.list) —
отдельные list-general/list-google на роутере не создаются. Блок MODE_* и ` + "`NFQWS_EXTRA_ARGS=$MODE_AUTO`" + `
сохранены: автохостлист (` + "`auto.list`" + ` + ` + "`--hostlist-auto-debug`" + `) продолжает работать —
главные TCP/QUIC-профили наследуют его через NFQWS_EXTRA_ARGS.
`)
	return b.String()
}
