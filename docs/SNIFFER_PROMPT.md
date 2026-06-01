# Идеальный промпт для нейросети: HTTP‑снифер на C# / .NET 10 поверх JAHTTPClient

Скопируйте целиком всё, что ниже разделителя `=====`, и передайте нейросети
(Claude / GPT / др.) как единое задание. Промпт самодостаточен: он описывает
фундамент (`JAHTTPClient`), архитектуру MITM‑прокси, веб‑интерфейс в стиле
Fiddler Everywhere, формат `.saz`, краевые случаи и критерии приёмки.

> Перед запуском задания добавьте проект `JAHTTPClient` в решение (он уже в этом
> репозитории) и убедитесь, что рядом со сборкой лежит нативная библиотека
> `tls-client-*.{dll,so}` (см. `native/` и корневой `README.md`).

=====================================================================

## Роль

Ты — senior .NET‑инженер. Построй **production‑ready** HTTP(S)‑снифер
(перехватывающий отладочный прокси) на **C# 13 / .NET 10**, аналог **Fiddler
Everywhere**, с веб‑интерфейсом, открывающимся в браузере на `localhost`.
Снифер ловит трафик обычных браузеров и **переотправляет каждый запрос наверх
через готовый клиент `JAHTTPClient`**, чтобы исходящее соединение несло
**настоящий TLS (JA3/JA4) и HTTP/2‑отпечаток Google Chrome 148** — в отличие от
Fiddler, чей .NET‑стек выдаёт «не‑браузерный» ClientHello и палится anti‑bot
системами (Akamai, Cloudflare).

Назначение — легальная отладка собственного веб‑трафика, тестирование API,
анализ редиректов и cookie. Это dual‑use инструмент уровня Fiddler / Charles /
mitmproxy.

## Технологический стек и ограничения

- **.NET 10**, **C# 13**, `Nullable enable`, `ImplicitUsings enable` (как в
  `Directory.Build.props` репозитория).
- Бэкенд: **ASP.NET Core (Kestrel)** + **SignalR** для real‑time push в UI.
- Прокси: собственный TCP‑listener (`System.Net.Sockets.TcpListener`), без
  сторонних прокси‑фреймворков.
- Сертификаты: `System.Security.Cryptography.X509Certificates`
  (`CertificateRequest`, корневой CA + лиф‑сертификаты на лету).
- Фронтенд: одностраничное приложение, **отдаётся как статика из `wwwroot`,
  без Node‑сборки** («просто `dotnet run`»). Допустим vanilla TS/JS или один
  лёгкий фреймворк, подключаемый файлом; клиент SignalR вендорится в `wwwroot`.
  Альтернатива — Blazor Server (тоже без Node), на твоё усмотрение.
- Весь сетевой код — асинхронный (`async`/`await`, `CancellationToken`),
  потокобезопасный. Никаких заглушек, `TODO` и «эллипсисов» — только рабочий код.
- Кроссплатформенность по возможности, но приоритет — **Windows** (там же
  тумблер системного прокси и установка CA).

## Фундамент: API `JAHTTPClient` (использовать как HTTP‑движок «наверх»)

`JAHTTPClient` уже реализован — **не переписывай его, а вызывай**. Это
`HttpClient`‑совместимый клиент с эмуляцией отпечатка Chrome. Реальная
поверхность API, которую нужно использовать:

```csharp
using JAHTTPClient;
using JAHTTPClient.Fingerprinting;

// Один потокобезопасный клиент можно шарить между соединениями (он держит
// нативную сессию = свой cookie‑jar и пул соединений). Создаётся так:
using var client = new TlsClientChromeHttpClient(new ChromeHttpClientOptions
{
    EnableJa3Fingerprinting   = true,
    FingerprintPreset         = Ja3Preset.Chrome,   // Chrome 148 (по умолчанию)
    AllowAutoRedirect         = false,              // для сниффинга см. «умные редиректы»
    MaxAutomaticRedirections  = 10,
    Timeout                   = TimeSpan.FromSeconds(100),
    MaxConcurrency            = 0,                   // 0 = без лимита; задай при массовом фан‑ауте
    // Proxy = "http://user:pass@host:port",        // апстрим‑прокси, если нужен
    // ForceHttp1 = true,                            // принудительный HTTP/1.1
    // InsecureSkipVerify = true,                    // НЕ включать без причины
});

// Главный примитив — повторяет HttpClient:
Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct = default);

// Живые переключатели (без пересоздания клиента, потокобезопасны, действуют со
// следующего запроса):
client.AllowAutoRedirect = true|false;          // вкл/выкл следование редиректам на лету
client.MaxAutomaticRedirections = n;            // длина цепочки
client.SetProxy("http://user:pass@host:port");  // горячая смена апстрим‑прокси (null = напрямую)
string? cur = client.Proxy;

// Cookies (поверх нативного jar сессии):
client.Cookies.SetCookie(url, name, value, path: "/", domain: null);
client.Cookies.AddRaw(url, "a=1; b=2");
client.Cookies.Import(url, cookieContainer);
IReadOnlyDictionary<string,string> ck = client.Cookies.GetCookies(url);
string json = client.Cookies.GetCookiesJson(indented: true); // экспорт в формате Cookie‑Editor
```

Ключевые опции `ChromeHttpClientOptions`: `EnableJa3Fingerprinting`,
`FingerprintPreset` (`Ja3Preset.Chrome`=148 / `ChromeLatest`=146 / `Edge` /
`Firefox` / `Safari`), `TlsIdentifier` (override, напр. `"chrome_146"`),
`AllowAutoRedirect`, `MaxAutomaticRedirections`, `Proxy`, `RotatingProxy`,
`DisableConnectionReuse`, `MaxRetries` (=2), `Timeout`, `InsecureSkipVerify`,
`ForceHttp1`, `MaxConcurrency`, `DefaultHeaders`, `Cookies`.

**Семантика, которую нужно знать (она же — фича «умных редиректов»):**

- Редиректы обрабатываются в **managed‑коде**, поэтому можно вернуть
  **промежуточный** ответ: `MaxAutomaticRedirections = 1` → контент/заголовки
  шага «проверка», а не финального. Cookie между хопами переносятся
  автоматически. `307/308` сохраняют метод и тело; `301/302/303` понижают
  не‑GET до GET; `Referer` проставляется на каждом хопе.
- `response.RequestMessage.RequestUri` — **финальный URL** после редиректов.
- `response.Version` — реально согласованный апстримом протокол (`2.0`/`1.1`).
- Набор заголовков нормализуется: h2‑несовместимые connection‑заголовки
  (`Connection`, `Keep-Alive`, `Proxy-Connection`, `Transfer-Encoding`,
  `Upgrade`, `TE`) выбрасываются (если не `ForceHttp1`); заголовки сортируются в
  каноничном порядке Chrome; client‑hints (`User-Agent`, `sec-ch-ua`, …)
  подмешиваются, но **заголовки запроса побеждают** значения пресета.
- **Тело ответа возвращается уже ДЕКОДИРОВАННЫМ (рас‑gzip/br/zstd), а заголовки
  `Content-Length` и `Content-Encoding` намеренно НЕ выставляются** на
  `response.Content`. Это критично при ретрансляции в браузер (см. F3).
- Клиент **буферизует** запрос/ответ целиком (нативный слой гоняет base64) —
  **нет потоковой передачи, нет нативной поддержки WebSocket/SSE/HTTP‑upgrade**.

## Архитектура

```
            ┌──────────── один процесс (.NET 10) ────────────┐
Браузер ──► │  MITM‑прокси :8866  ──(JAHTTPClient, Chrome JA3)─►  реальный сайт
(proxy=     │        │  захват сессии                          │
 127.0.0.1  │        ▼                                         │
 :8866)     │   капчер‑пайплайн ──► SignalR ──► Веб‑UI :8888  ◄── браузер (вкладка UI)
            └─────────────────────────────────────────────────┘
```

1. **Прокси слушает `127.0.0.1:8866`.** Веб‑интерфейс отдаётся на **отдельном
   порту** (по умолчанию `http://localhost:8888`) — открывается как обычный
   сайт. Оба сервиса — в одном процессе.
2. **Plain HTTP:** читаем absolute‑form запрос, переотправляем через
   `JAHTTPClient`, ретранслируем ответ.
3. **HTTPS через `CONNECT`:**
   - на `CONNECT host:443` отвечаем `HTTP/1.1 200 Connection Established`;
   - поднимаем **TLS как сервер**, предъявляя лиф‑сертификат для `host`,
     подписанный нашим корневым CA (его пользователь установит в доверенные);
   - расшифровываем HTTP‑запрос(ы) браузера (поддержать keep‑alive — несколько
     запросов в одном туннеле);
   - каждый — наверх через `JAHTTPClient` (настоящий TLS, Chrome JA3);
   - ответ отдаём обратно поверх клиент‑TLS.
4. **Развязка протоколов (важно!):** в ALPN, который прокси предлагает
   **браузеру**, оставляем **только `http/1.1`** — тогда браузер↔прокси всегда
   HTTP/1.1 (просто парсить), а прокси↔сайт использует `JAHTTPClient` (h2 по
   умолчанию, с отпечатком Chrome). Это и есть смысл связки: простой клиентский
   лег + фингерпринтованный апстрим‑лег. Версию апстрима бери из
   `response.Version` и показывай в UI.

## Функциональные требования (каждое — с критерием приёмки)

**F1. MITM‑прокси на `127.0.0.1:8866`.** Принимает HTTP и `CONNECT`; держит
много одновременных соединений; не падает на разрыве клиента.
*Критерий:* выставив системный/браузерный прокси на `127.0.0.1:8866`, трафик
ходит, сайты открываются.

**F2. Корневой CA + лиф‑сертификаты + UX доверия.** При первом старте
генерируем самоподписанный корневой CA (ECDSA P‑256 или RSA‑2048), **персистим**
(напр. `%APPDATA%/JASniffer/rootCA.pfx`). Лиф‑сертификаты на каждый host
генерируем на лету с правильным **SAN** и кэшируем в памяти. В UI — кнопка
**скачать CA** (`.cer`) и инструкция по установке (Windows cert store «Доверенные
корневые», Firefox — свой стор).
*Критерий:* после установки CA HTTPS‑сайты открываются без предупреждений, в
инспекторе виден расшифрованный трафик.

**F3. Апстрим через `JAHTTPClient` с отпечатком Chrome.** Переотправляй каждый
расшифрованный запрос так:

```csharp
// 'client' — общий потокобезопасный TlsClientChromeHttpClient.
// Для HTTPS‑туннеля absoluteUrl = "https://" + connectHost + requestTarget(path);
// для plain‑HTTP запрос уже в absolute‑form.
var upstream = new HttpRequestMessage(new HttpMethod(method), absoluteUrl);

// Заголовки браузера переносим ВЕРБАТИМ, в исходном порядке, разделяя на
// request- и content‑заголовки. Прокси‑специфичные (Proxy-*) — НЕ форвардить.
foreach (var (name, value) in browserHeadersInOrder)
{
    if (name.StartsWith("Proxy-", StringComparison.OrdinalIgnoreCase)) continue;
    if (IsContentHeader(name)) continue;            // повесим на Content ниже
    upstream.Headers.TryAddWithoutValidation(name, value);
}
if (bodyBytes is { Length: > 0 })
{
    upstream.Content = new ByteArrayContent(bodyBytes);
    foreach (var (name, value) in browserHeadersInOrder)
        if (IsContentHeader(name))
            upstream.Content.Headers.TryAddWithoutValidation(name, value);
}

// «Умные редиректы» — живой тумблер из UI, без пересоздания клиента:
client.AllowAutoRedirect = smartRedirectsEnabled;   // false = вернуть браузеру сырой 3xx

using var resp = await client.SendAsync(upstream, ct);
var respBytes  = await resp.Content.ReadAsByteArrayAsync(ct);

// КРИТИЧНО при ретрансляции в браузер: JAHTTPClient уже ДЕКОДИРОВАЛ тело и НЕ
// проставил Content-Encoding/Content-Length. Поэтому браузеру отдаём respBytes
// как есть, ставим корректный Content-Length = respBytes.Length и НЕ
// возвращаем Content-Encoding (иначе браузер попытается рас‑gzip‑ить уже
// распакованный текст). Hop-by-hop заголовки (Transfer-Encoding, Connection и
// т.п.) в браузер тоже не копируем; соединение — keep-alive с Content-Length.
```

*Критерий:* запрос на `https://tools.scrapfly.io/api/fp/ja3`, прошедший через
снифер, в ответе показывает JA3, соответствующий Chrome (а не .NET).

**F4. Умные авторедиректы с возможностью отключить.** Тумблер в UI:
- **OFF (рекомендуемый дефолт для верного сниффинга):** `client.AllowAutoRedirect
  = false` → браузер получает сырой `3xx` и сам идёт дальше; ты ловишь **каждый
  хоп** как отдельную сессию (максимально достоверно — как в Fiddler).
- **ON:** `client.AllowAutoRedirect = true` + `MaxAutomaticRedirections` → прокси
  сам проходит цепочку (managed‑редиректы `JAHTTPClient`) и отдаёт финальный
  ответ; в UI цепочку показываем свёрнутой (с финальным URL из
  `response.RequestMessage.RequestUri`).
*Критерий:* переключение мгновенно меняет поведение на новых запросах без
перезапуска; в обоих режимах cookie не теряются.

**F5. Real‑time веб‑UI (master‑detail, как Fiddler Everywhere).** Сессии
появляются в списке **вживую** (push через SignalR, батчинг апдейтов).
*Критерий:* открываешь сайт в браузере — строки появляются в UI без перезагрузки
страницы.

**F6. Инспекторы (точно повторить раскладку из Fiddler).** Правая панель =
**Request (сверху)** + **Response (снизу)**:
- Request‑табы: **Headers (N)**, **Params (N)** (query‑строка), **Cookies (N)**
  (разобранный `Cookie:`), **Raw**, **Body**, **Auth** (разбор `Authorization` /
  basic/bearer). Заголовки — таблица **Key / Value** с фильтром.
- Response‑табы: **Headers (N)**, **Cookies (N)** (разобранный `Set-Cookie`),
  **Raw**, **Preview**, **Body**.
- Бейджи: у запроса — версия HTTP, метод; у ответа — статус (цветной), версия
  HTTP, **размер тела** («BODY: 442.00 B»), и TLS/сертификат (см. подводные
  камни — показывать честно).
- **Body/Preview:** pretty‑print JSON, рендер HTML в песочнице (sandboxed
  `iframe`), показ картинок, hex для бинарных, корректная кодировка текста по
  `Content-Type`.

**F7. Клик по запросу = вся информация корректно.** По клику оба инспектора
заполняются **полностью и без искажений**: сырой запрос и сырой ответ
(заголовки + декодированное тело), разобранные cookie/params/auth, превью тела,
бейджи. Это явное требование заказчика — данные должны отображаться корректно.
*Критерий:* для любой пойманной сессии видно полный request и response, тело
читаемо, заголовки/куки/параметры разобраны.

**F8. Фильтры / поиск / очистка.** Фильтр по host, методу, статусу,
content‑type, полнотекст по URL/телу; кнопка очистки списка; (опц.) меню
колонок. Список **виртуализирован** (тысячи строк — как `#332` на скринах).

**F9. Экспорт в оригинальный формат `.saz`.** Кнопка «Export» сохраняет все /
отфильтрованные / выбранные сессии в `.saz`, **импортируемый обратно в Fiddler**.
Точная структура (ZIP):

```
archive.saz
├── [Content_Types].xml
├── _index.htm
└── raw/
    ├── 001_c.txt   (сырой запрос: request-line + заголовки + CRLFCRLF + тело)
    ├── 001_s.txt   (сырой ответ:  status-line + заголовки + CRLFCRLF + тело)
    ├── 001_m.xml   (метаданные сессии)
    ├── 002_c.txt …
    └── …
```

- Нумерация — с `001`, дополняется нулями, в порядке сессий.
- `[Content_Types].xml`:
  ```xml
  <?xml version="1.0" encoding="utf-8"?>
  <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
    <Default Extension="htm" ContentType="text/html" />
    <Default Extension="xml" ContentType="application/xml" />
    <Default Extension="txt" ContentType="text/plain" />
  </Types>
  ```
- `NNN_c.txt` — **origin‑form** request‑line для HTTPS (`GET /path?q HTTP/1.1`) +
  заголовок `Host:` (Fiddler восстановит схему); тело как есть.
- `NNN_s.txt` — `HTTP/1.1 200 OK` + заголовки + тело (байты как пойманы).
- `NNN_m.xml` — минимально валидные метаданные Fiddler:
  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <Session SID="1" BitFlags="0">
    <SessionTimers ClientConnected="2026-06-01T12:00:00.000"
                   ClientBeginRequest="2026-06-01T12:00:00.010"
                   ClientDoneRequest="2026-06-01T12:00:00.020"
                   ServerGotRequest="2026-06-01T12:00:00.030"
                   ServerBeginResponse="2026-06-01T12:00:00.200"
                   ServerDoneResponse="2026-06-01T12:00:00.250"
                   ClientBeginResponse="2026-06-01T12:00:00.260"
                   ClientDoneResponse="2026-06-01T12:00:00.270" />
    <PipeInfo />
    <SessionFlags>
      <SessionFlag N="x-clientip"  V="127.0.0.1" />
      <SessionFlag N="x-hostip"    V="..." />
      <SessionFlag N="x-responsebodytransferlength" V="..." />
      <SessionFlag N="x-egressport" V="..." />
    </SessionFlags>
  </Session>
  ```
- `_index.htm` — простой валидный HTML‑список сессий (Fiddler перегенерит при
  загрузке). Шифрование/пароль SAZ (DES/AES) — **опционально**, по умолчанию off.
*Критерий:* экспортированный `.saz` открывается в Fiddler Classic/Everywhere, и
там видны те же запросы/ответы.

**F10. Системный прокси + сквозной туннель для неподдерживаемого.**
- Тумблер «System Proxy»: на Windows выставляет WinINET‑прокси на
  `127.0.0.1:8866` (и аккуратно возвращает прежние настройки при выключении).
- **WebSocket / SSE / HTTP‑upgrade / CONNECT на не‑HTTP порты** `JAHTTPClient`
  не умеет (он буферизует, без стриминга) → делай **прозрачный сырой TCP‑туннель**
  (без инспекции), чтобы браузер продолжал работать; помечай такую сессию как
  «tunneled».
*Критерий:* сайты с websocket’ами и стримингом работают; снифер не ломает их.

## Модель данных пойманной сессии

`Id` (последовательный int), `StartedUtc`, `DurationMs`; **Request:** `Method`,
`Scheme`, `Host`, `Port`, `Path`, `Query`, `HttpVersion` (клиентский лег = 1.1),
упорядоченные `RequestHeaders`, `RequestBody` (байты), `RequestContentType`;
**Response:** `StatusCode`, `ReasonPhrase`, `HttpVersion` (из `response.Version`),
`ResponseHeaders`, `ResponseBody` (декодированные байты), `ResponseContentType`,
`BodyLength`; **Meta:** `FinalUrl`, `RedirectChain` (если умные редиректы on),
`FingerprintPreset` (Chrome 148), `ClientIp/Port`, `HostIp` (если резолвится),
`Error`, `WasTunneled`, `BodyTruncated`. Разобранные представления: query‑params,
request‑cookies, response `Set‑Cookie`, auth.

## Подводные камни — обязательно учесть

1. **Тело уже декодировано** `JAHTTPClient`’ом; не рас‑gzip‑ивай повторно, не
   шли браузеру `Content-Encoding`, пересчитывай `Content-Length` (см. F3).
2. **Браузер‑лег только HTTP/1.1** (ALPN `http/1.1`), апстрим — что согласует
   `JAHTTPClient` (бери `response.Version`).
3. **Cookie:** форвардь заголовок `Cookie` браузера как есть. Нативный jar
   клиента **всегда включён** и может «дописать» свои cookie. Чтобы не было
   перекрёстного загрязнения между разными вкладками/доменами при достоверном
   сниффинге — используй **короткоживущий клиент на соединение/хост** или
   небольшой пул клиентов; либо (если нужна строгая верность) минимально расширь
   `ChromeHttpClientOptions`/нативный payload опцией `withoutCookieJar` (нативный
   контракт это поддерживает). Поясни выбранный компромисс в README.
4. **TLS/сертификат в UI — честно.** `JAHTTPClient` не отдаёт согласованную
   версию TLS и цепочку сертификата апстрима. Надёжно показывай **версию HTTP**
   (`response.Version`); JA3/TLS выводи как производное от активного пресета
   (напр. «Chrome 148 · TLS 1.3 (assumed)») с явной пометкой; «CERTIFICATE
   VALID» показывай только если апстрим‑handshake прошёл без ошибки (либо опусти).
   Не выдумывай значения. Если нужна точность — расширь нативный слой.
5. **Соответствие браузер↔пресет.** Браузер шлёт свой `User-Agent`/`sec-ch-ua`,
   и они побеждают пресет — отлично, **если браузер Chrome** (как на скринах).
   Если нет — JA3 (Chrome) разойдётся с UA: либо подгони `FingerprintPreset`,
   либо перепиши UA. По умолчанию исходи из Chrome.
6. **Большие/стриминговые ответы** буферизуются целиком (память + base64) —
   ограничь объём тела, удерживаемого в памяти для превью; полные байты для
   экспорта храни во временных файлах; помечай `BodyTruncated`. Для явного
   стриминга — туннелируй (F10).
7. **Производительность:** ограничивай конкуренцию (`MaxConcurrency`), батчи
   SignalR‑пуши, виртуализируй грид; клиент потокобезопасен и сам поднимает
   floor пула потоков.
8. **Доверие к CA:** объясни пользователю установку корневого CA; без неё HTTPS
   будет с ошибками сертификата.

## Структура решения

- `src/JAHTTPClient/` — **существующий** движок (переиспользовать, не менять без
  крайней нужды; допустимо аккуратно добавить опцию обхода cookie‑jar).
- `src/JASniffer.Core/` — модели сессий, капчер‑пайплайн, генерация/кэш
  сертификатов, экспорт `.saz`.
- `src/JASniffer.Proxy/` — TCP‑listener `:8866`, разбор HTTP/`CONNECT`,
  TLS‑as‑server, ретрансляция через `JAHTTPClient`, сырой туннель.
- `src/JASniffer.Web/` — ASP.NET Core хост: статика `wwwroot` (SPA), REST
  (`/api/sessions`, `/api/export.saz`, `/api/ca.cer`, `/api/settings`), SignalR
  hub живых апдейтов. **Стартовый проект**, поднимает и UI (`:8888`), и
  прокси (`:8866`).
- `README.md` — сборка нативной либы, `dotnet run`, установка CA, настройка
  прокси в браузере/системе, использование, экспорт `.saz`.

## Definition of Done

- `dotnet run` поднимает прокси `:8866` и UI `:8888`; `http://localhost:8888`
  открывает интерфейс в браузере.
- После установки CA и настройки прокси на `127.0.0.1:8866` — браузинг HTTPS
  показывает живые сессии в UI.
- Исходящие запросы несут отпечаток Chrome 148 (проверка через
  `tools.scrapfly.io/api/fp/ja3` — JA3 как у Chrome).
- Клик по сессии показывает полный request+response, заголовки, cookie, params,
  превью тела и бейджи — корректно.
- Тумблер «умных редиректов» вживую меняет поведение (OFF = сырой 3xx браузеру и
  захват каждого хопа; ON = прокси проходит цепочку и отдаёт финал).
- «Export» отдаёт `.saz`, который импортируется в Fiddler.
- WebSocket/неподдерживаемое — туннелируется, браузер не ломается.
- Тела ретранслируются корректно (без двойного gzip), `Content-Length` верный.

## Формат сдачи

Полный исходный код всех проектов решения, готовый к `dotnet build`/`dotnet
run`, с README и комментариями в нетривиальных местах. Где требуется выбор —
прими разумное решение и явно укажи его в README. Никаких заглушек.
