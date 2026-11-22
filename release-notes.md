Конвертер стратегий Flowseal (zapret-discord-youtube) в конфиг NFQWS2-keenetic. Developed by TmInT.

## Файлы

- f2n-gui.exe — приложение с интерфейсом (запуск двойным кликом)
- f2n.exe — режим командной строки (см. f2n без аргументов)
- F2N.ico — иконка для ярлыков

## Требования

- Windows 10/11 с WebView2 (стандартно есть)
- На роутере: Entware + nfqws2-keenetic + включённый SSH Entware (обычно порт 222, пользователь root)

## Что делает

- Конвертирует .bat-стратегии Flowseal в каноничный nfqws2.conf (блобы инлайн — конфиг самодостаточен)
- Сохраняет штатный workflow списков NFQWS2 (user.list/exclude.list/auto.list/ipset.list) и работу автохостлиста
- Установка по SSH: бэкап конфига и списков → запись → дополнение списков → restart → статус; автооткат при сбое
- Управление службой: status/start/stop/restart, лог автохостлиста

## Сборка из исходников

- CLI: go build
- GUI: go build -tags desktop,production -ldflags "-H=windowsgui" в gui/
- Иконка: tools/mkico
