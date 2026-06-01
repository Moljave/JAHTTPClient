# JASniffer — HTTPS‑снифер с отпечатком Chrome поверх JAHTTPClient

**JASniffer** — перехватывающий отладочный прокси (аналог **Fiddler Everywhere**)
на **C# 13 / .NET 10** с веб‑интерфейсом в браузере. Он ловит трафик обычных
браузеров и **переотправляет каждый запрос наверх через `JAHTTPClient`**, поэтому
исходящее соединение несёт **настоящий TLS (JA3/JA4) и HTTP/2‑отпечаток Google
Chrome 148** — в отличие от Fiddler, чей .NET‑стек выдаёт «не‑браузерный»
ClientHello и палится anti‑bot системами (Akamai, Cloudflare).

> ⚖️ **Назначение — легальная отладка собственного веб‑трафика, тестирование API,
> анализ редиректов и cookie.** Это dual‑use инструмент уровня Fiddler / Charles /
> mitmproxy. Перехватывайте только тот трафик, на который у вас есть право.

```
            ┌──────────── один процесс (.NET 10) ────────────┐
Браузер ──► │  MITM‑прокси :8866 ──(JAHTTPClient, Chrome JA3)─►  реальный сайт
(proxy=     │        │  захват сессии                          │
 127.0.0.1  │        ▼                                         │
 :8866)     │   капчер‑пайплайн ──► SignalR ──► Веб‑UI :8888  ◄── браузер (вкладка UI)
            └─────────────────────────────────────────────────┘
```

Браузер↔прокси всегда **HTTP/1.1** (в ALPN прокси предлагает браузеру только
`http/1.1` — просто парсить), а прокси↔сайт идёт через `JAHTTPClient` (h2 по
умолчанию, с отпечатком Chrome). Версию апстрима берём из `response.Version` и
показываем в UI.

---

## Быстрый старт

### 1. Нативная библиотека `tls-client`

`JAHTTPClient` работает поверх нативной библиотеки utls (см. корневой
[`README.md`](README.md) и каталог [`native/`](native/)). Соберите её один раз —
`dotnet build` сам скопирует бинарь рядом со сборкой:

```bash
# Linux (нужен gcc):
cd native && make linux
#   → src/JAHTTPClient/runtimes/linux-x64/native/tls-client-linux-amd64.so

# Windows (нужен mingw‑w64 / tdm‑gcc):
cd native ; ./build-windows.ps1
#   → src/JAHTTPClient/runtimes/win-x64/native/tls-client-windows-64.dll
```

### 2. Запуск

Снифер — **отдельное решение** `JASniffer.sln` (исходники в каталоге `sniffer/`),
которое ссылается на движок `src/JAHTTPClient`. Сборка/запуск:

```bash
dotnet build -c Release JASniffer.sln                       # при желании собрать всё решение
dotnet run   -c Release --project sniffer/JASniffer.Web     # поднять снифер
```

Поднимутся **оба** сервиса в одном процессе:

| Сервис | Адрес | Назначение |
|---|---|---|
| Веб‑UI | `http://localhost:8888` | интерфейс (откроется в браузере автоматически) |
| MITM‑прокси | `127.0.0.1:8866` | сюда направляется трафик браузера/системы |

Порты переопределяются через конфиг/переменные окружения:
`JASniffer__UiPort`, `JASniffer__ProxyPort`, `JASniffer__CaDirectory`.

### 3. Установка корневого CA (обязательно для HTTPS)

При первом старте генерируется самоподписанный корневой CA (ECDSA P‑256) и
**персистится** в `%APPDATA%/JASniffer/rootCA.pfx` (Windows) или
`~/.config/JASniffer/rootCA.pfx` (Linux/macOS). Без доверия к нему HTTPS‑сайты
будут с предупреждением о сертификате.

1. В UI нажмите **Download CA** (или откройте `http://localhost:8888/api/ca.cer`).
2. Установите `.cer` как **доверенный корневой**:
   - **Windows:** `certmgr.msc` → «Доверенные корневые центры сертификации» →
     Импорт; либо `certutil -addstore -user Root JASniffer-rootCA.cer`.
   - **Firefox:** свой стор — Настройки → Приватность → Сертификаты → Импорт,
     отметить «Доверять при идентификации веб‑сайтов».
   - **macOS:** Keychain Access → System → Импорт → Always Trust.
   - **Linux:** скопировать в `/usr/local/share/ca-certificates/` (как `.crt`) и
     `sudo update-ca-certificates`.

### 4. Направление трафика на прокси

- **Тумблер «System Proxy»** (только Windows) — выставляет WinINET‑прокси на
  `127.0.0.1:8866` и аккуратно возвращает прежние настройки при выключении
  (UI и `localhost` исключены из проксирования).
- **Вручную** (любая ОС / конкретный браузер) — укажите HTTP‑прокси
  `127.0.0.1:8866` для HTTP и HTTPS. Добавьте `localhost` в исключения, чтобы UI
  и его SignalR‑сокет не шли через прокси.

Откройте любой сайт — строки появятся в UI **вживую**.

---

## Возможности (карта на требования)

| | Возможность |
|---|---|
| **F1** | MITM‑прокси на `127.0.0.1:8866`: HTTP и `CONNECT`, много одновременных соединений, не падает на разрыве клиента. |
| **F2** | Корневой CA + лиф‑сертификаты на лету (правильный SAN, кэш в памяти) + кнопка скачать CA и инструкция. |
| **F3** | Каждый расшифрованный запрос уходит наверх через `JAHTTPClient` с отпечатком **Chrome 148** (проверка: `tools.scrapfly.io/api/fp/ja3` через снифер показывает JA3 Chrome, а не .NET). |
| **F4** | Тумблер «умных редиректов»: **OFF** (дефолт) — браузер получает сырой `3xx` и идёт сам, ловим каждый хоп; **ON** — прокси проходит цепочку и отдаёт финал. Переключается на лету. |
| **F5** | Real‑time веб‑UI (master‑detail): сессии появляются вживую через SignalR (батчинг апдейтов). |
| **F6/F7** | Инспекторы Request (сверху) + Response (снизу): табы Headers/Params/Cookies/Auth/Raw/Body и Headers/Cookies/Raw/Preview/Body, бейджи (метод, статус, версия HTTP, размер тела, TLS), pretty‑JSON, HTML в песочнице, картинки, hex для бинарных. |
| **F8** | Фильтры (host/метод/статус/тип + полнотекст), очистка, **виртуализированный** грид на тысячи строк. |
| **F9** | Экспорт в оригинальный `.saz`, импортируемый обратно в Fiddler Classic/Everywhere. |
| **F10** | Тумблер System Proxy (Windows) + прозрачный **сырой TCP‑туннель** для WebSocket/SSE/HTTP‑upgrade и `CONNECT` на не‑HTTP порты (помечаются «tunneled»). |

---

## Экспорт `.saz`

Кнопка **Export .saz** сохраняет все (или отфильтрованные) сессии в архив
формата Fiddler:

```
JASniffer-YYYYMMDD-HHMMSS.saz   (ZIP)
├── [Content_Types].xml
├── _index.htm
└── raw/
    ├── 001_c.txt   (сырой запрос:  origin-form request-line + Host + заголовки + тело)
    ├── 001_s.txt   (сырой ответ:   HTTP/1.1 <status> + заголовки + ДЕКОДИРОВАННОЕ тело, Content-Length пересчитан)
    ├── 001_m.xml   (метаданные сессии Fiddler: SessionTimers + SessionFlags)
    └── 002_…
```

Файл открывается в Fiddler Classic/Everywhere — там видны те же запросы/ответы.
Туннелированные (неинспектированные) сессии в архив не попадают.

---

## Принятые решения и компромиссы

Где промпт допускал выбор — принято разумное решение и описано здесь.

### Cookie‑jar: два клиента вместо одного

`JAHTTPClient` держит нативный cookie‑jar на сессию. Чтобы общий клиент не
«дописывал» свои cookie и не загрязнял разные хосты/вкладки при достоверном
сниффинге, в `ChromeHttpClientOptions` **аккуратно добавлена опция
`WithoutCookieJar`** (нативный контракт `withoutCookieJar` это поддерживает —
единственное минимальное расширение движка). `UpstreamRelay` держит **два
долгоживущих потокобезопасных клиента** и выбирает нужный по тумблеру редиректов:

- **faithful** — редиректы **off**, **jar off**: браузер получает сырой `3xx` и
  идёт сам, каждый хоп — отдельная сессия, наверх уходят **ровно** cookie
  браузера (заголовок `Cookie` форвардится вербатим, никакого загрязнения).
  Это режим максимальной достоверности (дефолт).
- **follow** — редиректы **on**, **jar on**: цепочка проходится наверху, и
  нативный jar переносит `Set-Cookie` между хопами (иначе при следовании
  редиректам cookie бы терялись). В этом «удобном» режиме jar копит cookie за
  время жизни — приемлемо, т.к. он домен‑скоупленный, а режим не позиционируется
  как «дословный».

Пересоздания клиента при переключении нет (сохраняется пул соединений), смена
поведения — мгновенная, со следующего запроса.

### Честный TLS в UI

`JAHTTPClient` не отдаёт согласованную версию TLS и цепочку сертификата
апстрима. Поэтому показываем надёжное (**версию HTTP** из `response.Version`), а
TLS выводим как производное от активного пресета с явной пометкой —
`Chrome 148 · HTTP/2.0 · TLS 1.3 (assumed)`. Значения не выдумываются; бейдж
появляется только если апстрим‑обмен прошёл без транспортной ошибки.

### Тело уже декодировано

`JAHTTPClient` возвращает тело уже **рас‑gzip/br/zstd**, без `Content-Length` и
`Content-Encoding`. Браузеру отдаём байты как есть, ставим корректный
`Content-Length`, **не** возвращаем `Content-Encoding` и hop‑by‑hop заголовки —
иначе браузер попытался бы распаковать уже распакованное.

### Что туннелируется без инспекции

`JAHTTPClient` буферизует (без стриминга), поэтому **WebSocket / SSE /
HTTP‑upgrade** и `CONNECT` на не‑HTTP порты (≠ 443/8443) идут прозрачным сырым
TCP/TLS‑туннелем: браузер продолжает работать, сессия помечается «tunneled».
У такого туннеля апстрим‑лег не несёт Chrome‑JA3 (по определению — это сквозной
проброс без расшифровки).

### Память

Тела свыше `MaxBodyBytes` (по умолчанию 16 МБ) усекаются для превью и помечаются
`truncated`; **браузеру при этом всегда отдаётся полное тело** — усечение
касается только копии, удерживаемой для инспектора.

---

## Структура решения

Снифер вынесен в отдельный каталог `sniffer/` и собственное решение
`JASniffer.sln`; движок `src/JAHTTPClient` подключается по `ProjectReference` и
остаётся частью своего `JAHTTPClient.sln`.

```
JASniffer.sln            отдельное решение снифера (3 проекта + движок JAHTTPClient)
src/JAHTTPClient/        существующий движок (Chrome JA3). Минимальное добавление: опция WithoutCookieJar.
sniffer/JASniffer.Core/  модели сессий, SessionStore, генерация/кэш сертификатов (CertificateAuthority),
                         разбор (params/cookies/auth), экспорт .saz (SazExporter), настройки.
sniffer/JASniffer.Proxy/ TcpListener :8866, разбор HTTP/CONNECT (Http1Reader/Http1Request),
                         TLS‑as‑server, ретрансляция через JAHTTPClient (UpstreamRelay), сырой туннель.
sniffer/JASniffer.Web/   ASP.NET Core хост: статика wwwroot (SPA), REST API, SignalR hub,
                         прокси как hosted‑service. Стартовый проект.
```

SPA — vanilla JS/HTML/CSS из `wwwroot` (без Node‑сборки); клиент SignalR
вендорится в `wwwroot/lib/signalr.min.js`.

### REST API (для справки)

| Метод | Путь | Назначение |
|---|---|---|
| GET | `/api/status` | порты, CA, платформа, поддержка system‑proxy |
| GET/POST | `/api/settings` | умные редиректы, capture, upstream‑proxy |
| GET | `/api/sessions` | список сессий (summary) |
| GET | `/api/sessions/{id}` | полный detail (заголовки, parsed, тела) |
| GET | `/api/sessions/{id}/{request|response}-body` | сырые байты (`?download=1`) |
| POST | `/api/clear` | очистить список |
| GET | `/api/ca.cer` | скачать корневой CA (DER) |
| GET | `/api/export.saz` | экспорт (`?ids=1,2,3` — выбранные) |
| POST | `/api/system-proxy` | `{ "enabled": true|false }` (Windows) |
| WS | `/hub/sessions` | SignalR: события `sessions` / `cleared` |

---

## Проверка отпечатка

```bash
# Через снифер (прокси + наш CA) — JA3 должен совпасть с прямым вызовом JAHTTPClient:
curl --proxy http://127.0.0.1:8866 --cacert rootCA.pem https://tools.scrapfly.io/api/fp/ja3
```

`ja3_digest` в ответе совпадает с отпечатком Chrome (а не .NET/curl) — значит
апстрим‑лег несёт настоящий ClientHello Chrome 148.
