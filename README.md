# F2N — Flowseal → NFQWS 2 Converter Keenetic/Netcraze

Конвертер профилей [Flowseal/zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube)
(`.bat`) в каноничный конфиг [nfqws2-keenetic](https://github.com/nfqws/nfqws2-keenetic).

## Страница релиза

[Последняя версия](https://github.com/TmInT/Flowseal-to-NFQWS2-Converter/releases/latest)

## Краткий гайд по использованию

1. Выберите путь к `zapret-discord-youtube`
2. Выберите стратегию
3. Нажмите на кнопку "Конвертировать"
4. Введите свой пароль для доступа к Entware по SSH
5. Нажмите на кнопку "Установить на роутер"

<img width="1006" height="773" alt="F2N_Guide" src="https://github.com/user-attachments/assets/893ebddc-4b82-45bb-b863-4b26385f4f5e" />

После нажатия на кнопку "Установить на роутер" будет контрольный вопрос

<img width="1006" height="773" alt="F2N_Guide_2" src="https://github.com/user-attachments/assets/dc3b4a6a-ea31-4379-bce2-6c1ad78da1e2" />

По завершению процесса будет выведен результат

<img width="1006" height="773" alt="F2N_Guide_3" src="https://github.com/user-attachments/assets/4bd65142-0bcc-4949-8bdd-44f50ad077dc" />

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
- **Blob'ы инлайнятся hex'ом** в `NFQWS_BASE_ARGS` (`--blob=name:0x…`): конфиг
  самодостаточен, для установки на роутер не нужны отдельные файлы.
- **Установка — только по вашей команде**: CLI сохраняет каталог с файлами, отчётом
  и манифестом; GUI ставит по SSH (Entware): бэкап → конфиг → дополнение списков →
  restart → статус, при сбое — автооткат.

## Использование

```
f2n <папка-flowseal> <профиль.bat> [-o каталог] [-iface eth3] [-gf disabled|tcp|udp|all] [-strict] [-dry-run]
```

- `-gf disabled` (по умолчанию) — игровые профили пропускаются, порты 1024-65535
  не добавляются в очереди (меньше нагрузки на роутер).
- `-dry-run` — показать конфиг в stdout, ничего не писать.
- `-strict` — любое предупреждение = ошибка.

## Что переводится

Все 22 пресета Flowseal 1.10.4 конвертируются без единого предупреждения
(тест `TestAllPresetsConvertWithoutLoss`). Правила соответствия сверены с исходниками
zapret (winws) и Lua-библиотеками zapret2:

- `fake` (все `--dpi-desync-fake-*`, встроенные фейки winws, `!`, `fake-tls-mod`), `syndata`,
  `split2`/`multisplit`, `disorder2`/`multidisorder`, `split`/`fakedsplit`,
  `disorder`/`fakeddisorder` (с `fakedsplit-mod`), `hostfakesplit` (включая `altorder=1` —
  встраивается Lua-функцией в конфиг), `ipfrag2`, `udplen`, `rst`;
- fooling `ts`/`badseq`/`md5sig`/`badsum`/`datanoack`, `--dpi-desync-ttl`,
  `tcp-flags-set/unset`, `repeats`, `cutoff`/`start` → `--out-range`, `ip-id`,
  `any-protocol`, `--filter-tcp/udp/l7/l3`, `--hostlist*`, `--ipset*`;
- GameFilter (отключаемый), агрегация `--wf-tcp/--wf-udp` в `TCP_PORTS/UDP_PORTS`.

Смысл сохраняется, а не только имена: позиция разреза сдвигается на 1 (в nfqws2 она
задаёт начало следующей части), fooling искажает только фейки, реальные сегменты
уходят без изменений, `cutoff` стоит перед инстансами профиля.

Не переводится (даёт предупреждение, в `-strict` — ошибку): `--dpi-desync-autottl`,
`--wsize`/`--wssize`, `--dup*`, `--orig-*`, режимы `synack`, `hopbyhop`, `destopt`,
`ipfrag1`, `tamper`, `ip-id=seqgroup`. В пресетах Flowseal их нет.

## Тест стратегий (GUI, раздел 5)

Как «Run Tests» в service.bat у Flowseal, только на роутере: каждая выбранная
стратегия по очереди ставится на роутер и проверяется с этого ПК — Discord, YouTube,
Google (HTTP, TLS 1.2, TLS 1.3, ping) и набор dpi-checkers (заморозка после 16–20 КБ).
Итог = 70% цели + 30% DPI; базовый замер с остановленным nfqws2 показывает, что
заблокировано без обхода и что стратегия ломает. По окончании прежний конфиг и списки
возвращаются на место; если сессия оборвалась — следующая предложит восстановить.

## Сборка

```
go build -o f2n.exe .
go test ./...
```

Тестовые фикстуры: `testdata/flowseal/` (пресеты и списки из репозитория Flowseal),
`testdata/zapret2-lua/` (Lua-библиотеки zapret2 версии роутера — на них сгенерированные
инстансы прогоняются в настоящей Lua VM).
