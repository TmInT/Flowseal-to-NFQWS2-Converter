package convert

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"f2n/internal/flowseal"
)

const fixtureDir = "../../testdata/flowseal"

func presetNames(t *testing.T) []string {
	t.Helper()
	ents, err := os.ReadDir(fixtureDir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".bat") {
			names = append(names, strings.TrimSuffix(e.Name(), ".bat"))
		}
	}
	return names
}

func runPreset(t *testing.T, name, gf string) *Result {
	t.Helper()
	res, err := Run(Options{
		FlowsealDir: fixtureDir, BatFile: filepath.Join(fixtureDir, name+".bat"),
		Interface: "eth3", Policy: "nfqws", GameFilter: gf,
	})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return res
}

// Все пресеты Flowseal должны переводиться без потерь: ни один режим или
// параметр не отбрасывается, ни один профиль не подменяется заглушкой.
// Golden-файлы это не ловят — они сравнивают конвертер с самим собой.
func TestAllPresetsConvertWithoutLoss(t *testing.T) {
	loss := regexp.MustCompile(`не поддерживается|не имеет|заглушк|payload по умолчанию|blob=0x00000000|свёрнут|не воспроизводится`)
	for _, name := range presetNames(t) {
		for _, gf := range []string{"disabled", "all"} {
			res := runPreset(t, name, gf)
			for _, w := range res.Warnings {
				if loss.MatchString(w) {
					t.Errorf("%s (gf=%s): %s", name, gf, w)
				}
			}
		}
	}
}

// Позиция разреза: winws "1" = после первого байта = nfqws2 "2".
// pos=1 библиотека удаляет и разрез не происходит.
func TestSplitPositionIsShifted(t *testing.T) {
	badPos := regexp.MustCompile(`pos=1([,:"]|\s|$)`)
	for _, name := range presetNames(t) {
		conf := runPreset(t, name, "all").Conf
		if badPos.MatchString(conf) {
			t.Errorf("%s: устаревшая позиция разреза pos=1 на смещении %v", name, badPos.FindStringIndex(conf))
		}
	}
	conf := runPreset(t, "general (ALT11)", "all").Conf
	for _, want := range []string{
		"--lua-desync=multisplit:pos=2:seqovl=664:seqovl_pattern=tls_clienthello_www_sferum_ru",
		"--lua-desync=multisplit:pos=2:seqovl=681:seqovl_pattern=tls_clienthello_www_google_com:ip_id=zero",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("ALT11: нет %q", want)
		}
	}
	conf = runPreset(t, "general (ALT7)", "all").Conf
	if !strings.Contains(conf, "multisplit:pos=3,sniext+1:seqovl=679") {
		t.Errorf("ALT7: split-pos=2,sniext+1 должен стать pos=3,sniext+1")
	}
}

func TestConvPos(t *testing.T) {
	cases := map[string]string{
		"": "", "1": "2", "2,sniext+1": "3,sniext+1", "1,midsld": "2,midsld",
		"midsld": "midsld", "host,midsld": "host,midsld", "-10": "-10", "10,-10": "11,-10",
	}
	for in, want := range cases {
		if got := convPos(in); got != want {
			t.Errorf("convPos(%q) = %q, want %q", in, got, want)
		}
	}
}

// В winws fooling искажает только фейки. Реальные сегменты multisplit/multidisorder
// обязаны уходить без искажений, иначе сервер их отбросит.
func TestFoolingAppliesOnlyToFakes(t *testing.T) {
	split := regexp.MustCompile(`--lua-desync=(multi(split|disorder)):[^\n"]*`)
	tamper := regexp.MustCompile(`tcp_ts=|tcp_seq=|tcp_ack=|badsum|tcp_md5`)
	for _, name := range presetNames(t) {
		conf := runPreset(t, name, "all").Conf
		for _, line := range split.FindAllString(conf, -1) {
			if tamper.MatchString(line) {
				t.Errorf("%s: fooling попал в реальный сегмент: %s", name, line)
			}
		}
	}
}

// --out-range действует на последующие инстансы профиля, поэтому идёт первым.
func TestCutoffRangeGoesFirst(t *testing.T) {
	conf := runPreset(t, "general (ALT11)", "all").Conf
	for _, want := range []string{
		"--out-range=<n4\n            --payload=tls_client_hello\n",
		"--out-range=<n4\n            --payload=quic_initial",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("нет %q", want)
		}
	}
	// и не встречается после инстансов
	for _, line := range strings.Split(conf, "\n") {
		if strings.Contains(line, "--lua-desync=") && strings.Contains(line, "--out-range") {
			t.Errorf("out-range внутри строки инстанса: %s", line)
		}
	}
}

// Профиль без своих фейков получает встроенные фейки winws, а не заглушку.
func TestBuiltinFakes(t *testing.T) {
	conf := runPreset(t, "general (FAKE TLS AUTO)", "all").Conf
	for _, want := range []string{
		"--lua-init=f2n_tls_", "=tls_mod(f2n_fake_tls,'sni=www.google.com')",
		"--lua-desync=fake:blob=0x00000000:repeats=11:tcp_seq=-10000:tcp_ack=-66000",
		":tls_mod=rnd,dupsid:repeats=11:tcp_seq=-10000:tcp_ack=-66000",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("FAKE TLS AUTO: нет %q", want)
		}
	}
	conf = runPreset(t, "general (ALT8)", "all").Conf
	if !strings.Contains(conf, "fake:blob=f2n_fake_tls:repeats=6:tcp_seq=2:tcp_ack=-66000") {
		t.Errorf("ALT8: стандартный TLS-фейк с badseq-increment=2 не найден")
	}
	if strings.Contains(conf, "f2n_fake_tls:tls_mod") {
		t.Errorf("ALT8: fake-tls-mod=none не должен давать tls_mod")
	}
	conf = runPreset(t, "general (ALT11)", "all").Conf
	if !strings.Contains(conf, "fake:blob=f2n_fake_http:repeats=8:tcp_ts=-600000") {
		t.Errorf("ALT11: для профиля без fake-http нужен стандартный HTTP-фейк")
	}
}

// altorder=1 в nfqws2 нет — функция встраивается в конфиг.
func TestAltorderIsEmbedded(t *testing.T) {
	conf := runPreset(t, "general (ALT3)", "all").Conf
	if !strings.Contains(conf, "--lua-init=assert(loadstring(parse_hex('") {
		t.Errorf("ALT3: нет встроенной lua-функции altorder")
	}
	for _, want := range []string{
		"--lua-desync=f2n_hfs_alt:host=www.google.com:tcp_ts=-600000:tcp_ts_up",
		"--lua-desync=f2n_hfs_alt:host=ya.ru:tcp_ts=-600000:tcp_ts_up:payload=~empty",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("ALT3: нет %q", want)
		}
	}
	if strings.Contains(conf, "--lua-desync=hostfakesplit:") {
		t.Errorf("ALT3: altorder=1 не должен превращаться в обычный hostfakesplit")
	}
	for _, name := range []string{"general (ALT11)", "general (ALT13)"} {
		c := runPreset(t, name, "all").Conf
		if strings.Contains(c, "f2n_hfs_alt") != (name == "general (ALT13)") {
			t.Errorf("%s: неожиданное наличие/отсутствие f2n_hfs_alt", name)
		}
	}
}

// syndata работает на SYN — пустом пакете; фильтр payload не должен его отсекать.
func TestSyndataIsNotPayloadFiltered(t *testing.T) {
	conf := runPreset(t, "general (ALT7)", "all").Conf
	if !strings.Contains(conf, "--payload=all\n            --lua-desync=syndata\n") {
		t.Errorf("ALT7: syndata должен идти с --payload=all")
	}
	conf = runPreset(t, "general (ALT5)", "all").Conf
	for _, want := range []string{"--filter-l3=ipv4", "--lua-desync=syndata", "--lua-desync=multidisorder"} {
		if !strings.Contains(conf, want) {
			t.Errorf("ALT5: нет %q", want)
		}
	}
}

// Конфиг разбирается шеллом init-скрипта: аргументы делятся по пробелам,
// а в NFQWS_BASE_ARGS запрещён --new.
func TestConfigIsShellSafe(t *testing.T) {
	luaName := regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)
	for _, name := range presetNames(t) {
		conf := runPreset(t, name, "all").Conf
		start := strings.Index(conf, "NFQWS_BASE_ARGS=\"")
		end := strings.Index(conf[start:], "\"\n")
		base := conf[start : start+end]
		if strings.Contains(base, "--new") {
			t.Errorf("%s: --new внутри NFQWS_BASE_ARGS", name)
		}
		for _, line := range strings.Split(base, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "--blob=") && !luaName.MatchString(strings.TrimPrefix(strings.SplitN(line, ":", 2)[0], "--blob=")) {
				t.Errorf("%s: имя блоба не lua-идентификатор: %s", name, line)
			}
			if strings.HasPrefix(line, "--lua-init=") && strings.ContainsAny(line, " \t\"$`\\") {
				t.Errorf("%s: небезопасный lua-init: %s", name, line)
			}
		}
	}
}

// Синтетические профили: пути, которых нет в пресетах Flowseal.
func TestMapProfileEdgeCases(t *testing.T) {
	b := newBlobStore("")
	join := func(a []string) string { return strings.Join(a, "\n") }

	// fake без своих фейков и без fake-tls-mod: встроенный ClientHello с модами по умолчанию
	p := &flowseal.Profile{FilterTCP: []string{"443"}, Desync: []string{"fake"}}
	m := mapProfile(p, b)
	if got := join(m.args); !strings.Contains(got, "--lua-desync=fake:blob=f2n_tls_") || !strings.Contains(got, ":tls_mod=rnd,dupsid") {
		t.Errorf("моды стандартного TLS-фейка по умолчанию:\n%s", got)
	}
	if len(m.inits) != 1 || !strings.Contains(m.inits[0], "=tls_mod(f2n_fake_tls,'rndsni')") {
		t.Errorf("rndsni должен применяться при старте: %v", m.inits)
	}

	// старые имена режимов winws: split = fakedsplit, disorder = fakeddisorder
	p = &flowseal.Profile{FilterTCP: []string{"443"}, Desync: []string{"fake", "split", "disorder"}, SplitPos: "1", Fooling: []string{"badseq"}}
	m = mapProfile(p, b)
	for _, want := range []string{"--lua-desync=fakedsplit:pos=2:tcp_seq=-10000:tcp_ack=-66000:tcp_ts_up", "--lua-desync=fakeddisorder:pos=2:tcp_seq=-10000"} {
		if !strings.Contains(join(m.args), want) {
			t.Errorf("нет %q в:\n%s", want, join(m.args))
		}
	}

	// fakedsplit-mod=altorder=N убирает часть фейков
	p = &flowseal.Profile{FilterTCP: []string{"443"}, Desync: []string{"fakedsplit"}, FakedsplitMod: "altorder=3"}
	if got := join(mapProfile(p, b).args); !strings.Contains(got, "fakedsplit:nofake1:nofake2:nofake4:tcp_ts_up") {
		t.Errorf("altorder=3: %s", got)
	}

	// start и cutoff в одном диапазоне
	p = &flowseal.Profile{FilterTCP: []string{"443"}, Desync: []string{"multisplit"}, DesyncStart: "n2", Cutoff: "n4"}
	if got := mapProfile(p, b).args[0]; got != "--out-range=n2-<n4" {
		t.Errorf("start+cutoff = %q", got)
	}

	// неподдерживаемый режим — предупреждение, а не молчание
	p = &flowseal.Profile{FilterTCP: []string{"443"}, Desync: []string{"synack"}}
	if m := mapProfile(p, b); len(m.warns) != 1 || !strings.Contains(m.warns[0], "synack") {
		t.Errorf("неизвестный режим должен предупреждать: %v", m.warns)
	}
}

// Исходник altorder уходит в конфиг hex'ом: байты не должны зависеть от того,
// с какими переводами строк файл выгрузил git (CRLF на CI под Windows).
func TestAltorderInitIgnoresLineEndings(t *testing.T) {
	lf := hex.EncodeToString([]byte(altorderLua))
	crlf := hex.EncodeToString([]byte(strings.ReplaceAll(altorderLua, "\n", "\r\n")))
	if lf == crlf {
		t.Fatal("в исходнике нет переводов строк — проверять нечего")
	}
	// тест остаётся зелёным и когда рабочая копия файла выгружена с CRLF
	if !strings.Contains(altorderInit, lf) || strings.Contains(altorderInit, crlf) {
		t.Errorf("hex в конфиге зависит от переводов строк (в рабочей копии CRLF: %v)", strings.Contains(altorderLuaRaw, "\r"))
	}
}
