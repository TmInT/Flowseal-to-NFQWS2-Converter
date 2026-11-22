# F2N — Flowseal → NFQWS 2 Converter Keenetic/Netcraze

Конвертер профилей [Flowseal/zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube)
(`.bat`) в каноничный конфиг [nfqws2-keenetic](https://github.com/nfqws/nfqws2-keenetic).

## Страница релиза

[Последняя версия](https://github.com/TmInT/Flowseal-to-NFQWS2-Converter/releases/latest)

## Философия

- **Списки остаются как задумано в NFQWS 2**: домены Flowseal сливаются в штатные
  `user.list` / `exclude.list` / `ipset.list` / `ipset_exclude.list`, отдельные
  `list-general.txt`/`list-google.txt` на роутере не создаются.
- **Автохостлист не теряется**: блок `MODE_*` и `NFQWS_EXTRA_ARGS="$MODE_AUTO"`
  сохраняются, главный TCP/QUIC-профили наследуют `user.list` + `auto.list`
  (`--hostlist-auto` + `--hostlist-auto-debug` — логирование проблемных подключений).
- **Профили раскладываются по штатным слотам**: главный TCP → `NFQWS_ARGS`,
  главный QUIC → `NFQWS_ARGS_QUIC`, спец-UDP → `NFQWS_ARGS_UDP`,
  спец-профили → `NFQWS_ARGS_CUSTOM` (инлайн-домены), ipset-профили с той же
  стратегией сворачиваются в `NFQWS_ARGS_IPSET`.
- **Blob'ы — файлами** в `blobs/` (→ `/opt/etc/nfqws2/blobs/`), а не inline-hex.
- **Ничего не пишется на роутер самовольно**: результат — каталог с файлами,
  отчётом и манифестом; установка — вручную по REPORT.md (или позже через `--deploy`).

## Использование

```
f2n <папка-flowseal> <профиль.bat> [-o каталог] [-iface eth3] [-gf disabled|tcp|udp|all] [-strict] [-dry-run]
```

- `-gf disabled` (по умолчанию) — игровые профили пропускаются, порты 1024-65535
  не добавляются в очереди (меньше нагрузки на роутер).
- `-dry-run` — показать конфиг в stdout, ничего не писать.
- `-strict` — любое предупреждение = ошибка.

## Что вошло в MVP

- `fake`, `multisplit` (+замена `split`/`split2`), `multidisorder`, `fakedsplit`,
  `fakeddisorder`, `hostfakesplit` (приблизительно), fooling `ts`/`badseq`/`md5sig`/`badsum`,
  `repeats`, `cutoff` → `--out-range=<nN`, `ip-id=zero`, `any-protocol`, все
  `--dpi-desync-fake-*` источники, `--filter-tcp/udp/l7`, `--hostlist-domains`,
  GameFilter (отключаемый), агрегация `--wf-tcp/--wf-udp` в `TCP_PORTS/UDP_PORTS`.

## Не вошло (этап 2)

- `hostfakesplit altorder/nfsize` (нужна lua-функция совместимости), `fake-tls-mod`,
  экспериментальные пресеты `FAKE TLS AUTO` (payload/lua-специфика), `blockcheck`-интеграция,
  автоматический деплой через веб-API nfqws-keenetic-web.

## Сборка

```
go build -o f2n.exe .
go test ./...
```

Тестовые фикстуры: `testdata/flowseal/` (пресеты и списки из репозитория Flowseal).
