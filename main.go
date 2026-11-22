// f2n — Flowseal (zapret-discord-youtube) → NFQWS2-keenetic converter.
//
// Конвертирует .bat-профиль Flowseal в каноничный nfqws2.conf и умеет
// устанавливать результат на роутер по SSH (Entware):
//   бэкап → запись конфига (блобы inline) → слияние списков → restart → status.
package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"f2n/internal/convert"
	"f2n/internal/sshctl"
)

const usage = `f2n — конвертер профилей Flowseal (zapret-discord-youtube) в конфиг nfqws2-keenetic

Использование:
  f2n <папка-flowseal> <профиль.bat> [флаги]            конвертация
  f2n <папка-flowseal> <профиль.bat> -ssh-deploy        конвертация + установка по SSH
  f2n -ssh-status                                        статус службы на роутере
  f2n -ssh-restart                                       перезапуск службы
  f2n -ssh-log                                           хвост лога автохостлиста

Флаги:
  -o путь        каталог результата (по умолчанию ./converted)
  -iface имя     WAN-интерфейс роутера (по умолчанию eth3)
  -policy имя    имя политики Keenetic (по умолчанию nfqws)
  -gf режим      Game Filter: disabled|tcp|udp|all (по умолчанию disabled)
  -strict        считать любое предупреждение ошибкой
  -dry-run       только показать конфиг, ничего не писать

SSH (Entware, порт 22):
  -ssh-host IP   адрес роутера (по умолчанию 192.168.1.1)
  -ssh-port N    порт SSH (по умолчанию 22)
  -ssh-user      пользователь (по умолчанию root)
  -ssh-pass      пароль (иначе будет запрошен)
  -ssh-status    статус службы (S51nfqws2 status + iptables)
  -ssh-restart   перезапуск службы
  -ssh-log       последние 50 строк лога автохостлиста
  -ssh-deploy    установить: бэкап → конфиг → списки → restart → status
  -deploy-check  проверить SSH-доступ и запись, ничего не меняя
`

func main() {
	var pos []string
	out, iface, policy, gf := "converted", "eth3", "nfqws", "disabled"
	strict, dryRun, sshDeploy, checkOnly := false, false, false, false
	sshMode := ""
	sshHost, sshUser, sshPass := "192.168.1.1", "root", ""
	sshPort := 222

	boolFlags := map[string]*bool{
		"-strict": &strict, "-dry-run": &dryRun,
		"-ssh-status": new(bool), "-ssh-restart": new(bool), "-ssh-log": new(bool),
		"-ssh-deploy": &sshDeploy, "-deploy-check": &checkOnly, "-deploy": &sshDeploy,
	}
	valFlags := map[string]*string{
		"-o": &out, "-iface": &iface, "-policy": &policy, "-gf": &gf,
		"-ssh-host": &sshHost, "-ssh-user": &sshUser, "-ssh-pass": &sshPass,
		"-ssh-mode": &sshMode,
	}

	argv := os.Args[1:]
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if b, ok := boolFlags[a]; ok {
			*b = true
			if a == "-ssh-status" {
				sshMode = "status"
			} else if a == "-ssh-restart" {
				sshMode = "restart"
			} else if a == "-ssh-log" {
				sshMode = "log"
			}
			continue
		}
		if p, ok := valFlags[a]; ok {
			if i+1 >= len(argv) {
				fmt.Fprintf(os.Stderr, "f2n: флаг %s требует значение\n", a)
				os.Exit(2)
			}
			*p = argv[i+1]
			i++
			continue
		}
		if strings.HasPrefix(a, "-") {
			fmt.Fprintf(os.Stderr, "f2n: неизвестный флаг %s\n", a)
			os.Exit(2)
		}
		pos = append(pos, a)
	}
	if strings.HasPrefix(sshMode, "-") || sshMode == "" && checkOnly {
		// sanity
	}
	gf = strings.ToLower(gf)
	switch gf {
	case "disabled", "tcp", "udp", "all":
	default:
		fmt.Fprintf(os.Stderr, "f2n: -gf должен быть disabled|tcp|udp|all\n")
		os.Exit(2)
	}
	if p, err := strconv.Atoi(os.Getenv("F2N_SSH_PORT")); err == nil && p > 0 {
		sshPort = p
	}

	sc := sshctl.New(sshctl.Options{Host: sshHost, Port: sshPort, User: sshUser, Pass: sshPass})

	// --- чисто SSH-режимы (конвертация не нужна) ---
	switch sshMode {
	case "status", "restart", "log":
		if sshPass == "" {
			sshPass = promptPass()
		}
		sc2 := sshctl.New(sshctl.Options{Host: sshHost, Port: sshPort, User: sshUser, Pass: sshPass})
		switch sshMode {
		case "status":
			out, err := sc2.Status()
			fmt.Println(out)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		case "restart":
			out, err := sc2.Service("restart")
			fmt.Println(out)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			time.Sleep(3 * time.Second)
			st, _ := sc2.Service("status")
			fmt.Println(st)
		case "log":
			out, err := sc2.LogTail(50)
			fmt.Println(out)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
		return
	}

	if len(pos) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	dir, bat := pos[0], pos[1]

	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		fmt.Fprintf(os.Stderr, "f2n: папка Flowseal не найдена: %s\n", dir)
		os.Exit(2)
	}
	if _, err := os.Stat(bat); err != nil {
		cand := filepath.Join(dir, bat)
		if _, err2 := os.Stat(cand); err2 != nil {
			fmt.Fprintf(os.Stderr, "f2n: батник не найден: %s\n", bat)
			os.Exit(2)
		}
		bat = cand
	}

	if sshDeploy || checkOnly {
		if sshPass == "" {
			sshPass = promptPass()
		}
		sc = sshctl.New(sshctl.Options{Host: sshHost, Port: sshPort, User: sshUser, Pass: sshPass})
		// проверка доступа до конвертации
		if _, err := sc.Run("test -f " + sshctl.ConfPath + " && echo ok"); err != nil {
			fmt.Fprintf(os.Stderr, "f2n: SSH: %v\n", err)
			os.Exit(1)
		}
		if checkOnly {
			fmt.Println("SSH: доступ есть, конфиг найден. Полная проверка записи будет выполнена при деплое.")
			return
		}
	}

	opts := convert.Options{
		FlowsealDir: dir,
		BatFile:     bat,
		OutputDir:   out,
		Interface:   iface,
		Policy:      policy,
		GameFilter:  gf,
		Strict:      strict,
		DryRun:      dryRun,
	}

	res, err := convert.Run(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "f2n: ошибка: %v\n", err)
		os.Exit(1)
	}

	if dryRun {
		fmt.Print(res.Conf)
	} else {
		files, err := convert.WriteOutputs(opts, res)
		if err != nil {
			fmt.Fprintf(os.Stderr, "f2n: ошибка записи: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Записано:")
		for _, f := range files {
			fmt.Println("  " + f)
		}
	}

	if len(res.SlotTable) > 0 {
		fmt.Println("\nПрофили:")
		for _, l := range res.SlotTable {
			fmt.Println(l)
		}
	}
	if len(res.Infos) > 0 {
		fmt.Println("\nЗаметки:")
		for _, w := range res.Infos {
			fmt.Println("  ℹ " + w)
		}
	}
	if len(res.Warnings) > 0 {
		fmt.Println("\nПредупреждения:")
		for _, w := range res.Warnings {
			fmt.Println("  ⚠ " + w)
		}
	}
	if strict && len(res.Warnings) > 0 {
		fmt.Fprintf(os.Stderr, "\nf2n: strict-режим: предупреждения трактуются как ошибки\n")
		os.Exit(1)
	}

	// --- установка по SSH ---
	if sshDeploy && !dryRun {
		fmt.Printf("\nУстановка на %s (SSH)...\n", sshHost)
		conf := res.Conf
		bak, err := sc.WriteConf(conf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "f2n: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("  ✓ Бэкап: " + bak)

		adds, _ := convert.ListAdditions(dir)
		total := 0
		for _, name := range []string{"user.list", "exclude.list", "ipset.list", "ipset_exclude.list"} {
			n, err := sc.MergeList(name, adds[name])
			if err != nil {
				fmt.Fprintf(os.Stderr, "f2n: списки: %v\n", err)
				os.Exit(1)
			}
			total += n
			fmt.Printf("  ✓ Список %s: +%d строк\n", name, n)
		}
		_ = total

		out, err := sc.Service("restart")
		fmt.Println("  ✓ Restart: " + firstLine(out))
		if err != nil {
			fmt.Fprintf(os.Stderr, "f2n: restart: %v\n", err)
			fmt.Fprintln(os.Stderr, "  Откат: cp "+bak+" "+sshctl.ConfPath+" и повторный restart")
			os.Exit(1)
		}
		time.Sleep(3 * time.Second)
		st, _ := sc.Service("status")
		fmt.Println("  ✓ Статус: " + firstLine(st))
		ipt, _ := sc.Run("iptables-save 2>/dev/null | grep -c nfqws")
		fmt.Println("  ✓ Правил nfqws в iptables: " + ipt)
		fmt.Println("\nГотово. Проверьте Discord/YouTube с клиента.")
	} else if checkOnly {
		fmt.Println("SSH доступ проверен (см. выше). Конвертация не выполнялась.")
	}
	fmt.Println("\nГотово. Установка — см. REPORT.md в каталоге результата.")
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "\n"); i >= 0 {
		s = s[:i]
	}
	return s
}

func promptPass() string {
	fmt.Print("Пароль SSH роутера: ")
	sc := bufio.NewScanner(os.Stdin)
	sc.Scan()
	return strings.TrimSpace(sc.Text())
}

