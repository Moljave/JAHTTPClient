# JAHTTPClient

`HttpClient`-совместимый HTTP-клиент для **.NET 10 / C# 13**, который полностью
эмулирует **TLS (JA3/JA4)** и **HTTP/2** fingerprint **Google Chrome 148** и тем
самым проходит anti-bot системы (Akamai Bot Manager, Cloudflare), фильтрующие
запросы по ClientHello.

> 🕵️ **JASniffer** — построенный поверх этого движка отладочный HTTPS-снифер
> (аналог Fiddler Everywhere) с веб-интерфейсом: ловит трафик браузера и
> переотправляет его наверх с отпечатком Chrome 148. Это **отдельный проект**
> (своё решение `JASniffer.sln`, исходники в каталоге [`sniffer/`](sniffer/)).
> Запуск: `dotnet run -c Release --project sniffer/JASniffer.Web`. Подробности —
> [**JASNIFFER.md**](JASNIFFER.md).

## Почему не `SslStream` / `SocketsHttpHandler`

Стандартный TLS-стек .NET (SChannel на Windows) не даёт управлять порядком
cipher suites, набором и **порядком extensions** (Chrome их перемешивает),
GREASE, post-quantum key share `X25519MLKEM768`, padding и ALPN. JA3/JA4 у .NET
поэтому всегда «не браузерный» → детект. Это подтверждено диагностикой: Go-TLS →
`403`, тот же IP+заголовки через **uTLS Chrome** → `200`.

## Архитектура

P/Invoke-обёртка над нативной библиотекой
[`bogdanfinn/tls-client`](https://github.com/bogdanfinn/tls-client) (Go + utls),
собранной из исходников в `-buildmode=c-shared`. utls воспроизводит ClientHello
Chrome байт-в-байт; tls-client добавляет корректный HTTP/2-профиль (SETTINGS и их
порядок, WINDOW_UPDATE, priority frames, порядок псевдозаголовков
`:method`,`:authority`,`:scheme`,`:path`). Managed-слой только маршалит JSON и
строит `HttpResponseMessage`.

```
HttpRequestMessage → JSON → native request() (utls) → JSON → HttpResponseMessage
                                  ↑ cookie jar на sessionId
```

## Сборка

### 1. Нативная библиотека

Нужны **Go 1.23+** и C-компилятор (CGO).

**Windows** (основная платформа; нужен gcc — tdm-gcc или mingw-w64):

```powershell
cd client/native
./build-windows.ps1
# → client/JAHTTPClient/runtimes/win-x64/native/tls-client-windows-64.dll
```

**Linux** (нужен gcc):

```bash
cd client/native
make linux
# → client/JAHTTPClient/runtimes/linux-x64/native/tls-client-linux-amd64.so
```

> Готовые бинарники для **linux-x64** и **win-x64** уже закоммичены (исключения в
> `.gitignore`), так что проект работает «из коробки». `dotnet build` копирует нужный
> рядом со сборкой автоматически; пересобрать можно скриптами выше.

### 2. Решение

```bash
dotnet build -c Release JAHTTPClient.sln
```

## Использование

```csharp
using var client = new TlsClientChromeHttpClient(new ChromeHttpClientOptions
{
    EnableJa3Fingerprinting = true,
    FingerprintPreset       = Ja3Preset.Chrome,   // Chrome 148
    AllowAutoRedirect       = true,
    MaxAutomaticRedirections = 1,                 // см. семантику ниже
    // Proxy = "http://user:pass@host:port",
});

using var request = new HttpRequestMessage(HttpMethod.Get, "https://tools.scrapfly.io/api/fp/ja3");
using var response = await client.SendAsync(request);
var body = await response.Content.ReadAsStringAsync();
```

API намеренно повторяет `HttpClient` (`HttpRequestMessage`,
`HttpResponseMessage`, `CancellationToken`), поэтому существующий
`ExecuteShortWEBRequestAsync` переносится почти без изменений (пример — фрагмент выше).

### Семантика `MaxAutomaticRedirections`

Редиректы обрабатываются в managed-коде, поэтому можно вернуть **промежуточный**
ответ. Для цепочки `авторизация → проверка → финиш`:

| Значение | Результат |
|---|---|
| `10` (по умолч.) | ответ последнего шага («финиш») |
| `1` | контент и заголовки шага «проверка» |
| `AllowAutoRedirect = false` | первый `3xx` как есть |

Куки между хопами переносятся автоматически (один нативный jar на сессию).

Опции `AllowAutoRedirect` / `MaxAutomaticRedirections` задают **стартовую**
политику, но их можно менять **на ходу** прямо на клиенте (live-переключатель
между запросами):

```csharp
private void ChangeRedirectionState(bool enabled) => client.AllowAutoRedirect = enabled;

client.AllowAutoRedirect = false;     // следующий запрос вернёт первый 3xx как есть
client.MaxAutomaticRedirections = 5;  // ограничить длину цепочки
```

### Куки

- Серверные куки (`_abck`, `ak_bmsc`, `bm_sz`, `cf_clearance`) персистятся
  автоматически в нативном jar на время жизни клиента.
- Пользовательские куки: `client.Cookies.SetCookie(...)`,
  `client.Cookies.AddRaw(url, "a=1; b=2")`, `client.Cookies.Import(url, cookieContainer)`.
  При совпадении имени пользовательская кука перекрывает серверную.
- Чтение: `client.Cookies.GetCookies(url)`.
- **Сохранение/экспорт**: `client.Cookies.GetCookiesJson()` сериализует все
  накопленные за сессию куки (со всех доменов) в JSON в формате браузерных
  расширений (Cookie-Editor / EditThisCookie) — можно сохранить в файл и позже
  переимпортировать. `GetCookiesJson(url)` — только куки для конкретного URL,
  `GetCookiesJson(indented: true)` — с отступами. Метаданные (домен, путь, срок,
  `Secure`, `HttpOnly`) восстанавливаются из заголовков `Set-Cookie` ответов.

### Заголовки

Перед отправкой набор заголовков нормализуется:

- **HTTP/2-несовместимые** connection-заголовки (`Connection`, `Keep-Alive`,
  `Proxy-Connection`, `Transfer-Encoding`, `Upgrade`, `TE`) отбрасываются —
  иначе нативный h2-транспорт отклоняет весь запрос
  (`http2: invalid Connection request header`). Реальный браузер их по h2 не
  шлёт. При `ForceHttp1 = true` они сохраняются (валидны для HTTP/1.1).
- Значение, в которое случайно «склеился» целый блок заголовков (встречается,
  когда сырой блок из devtools/Burp добавлен одним заголовком с `\n`-разделителями),
  **разворачивается** обратно в отдельные заголовки, а не уходит как одно битое
  значение.

### Многопоточность и прокси

Нативный слой делает реальный async I/O, поэтому один клиент тянет тысячи
параллельных запросов. Каждый ответ освобождается (`freeMemory`), каждая сессия
закрывается на `Dispose` (`destroySession`) — без утечек. Прокси задаётся в
опциях (`Proxy`, `RotatingProxy`). При экстремальном фан-ауте можно ограничить
число одновременных запросов через `MaxConcurrency` (по умолчанию без лимита).

#### Ротационные прокси и ошибки `EOF`

При работе через **ротационный** прокси в многопоточности типична ошибка вида
`failed to do request: Get "...": EOF`. Причина: keep-alive соединения в пуле
привязаны к одному exit-IP; как только прокси сменил IP, переиспользованное из
пула соединение уже мертво → `EOF`. Решается на двух уровнях, оба включены по
умолчанию:

- **`DisableConnectionReuse`** (`bool?`, по умолч. `null` = «авто») — отключает
  пул keep-alive, каждый запрос дозванивается заново. В режиме «авто»
  автоматически включается при `RotatingProxy = true`. Куки-jar сессии (токены
  Akamai/Cloudflare) при этом сохраняется — отключается только пул соединений.
- **`MaxRetries`** (по умолч. `2`) — прозрачные ретраи **только** транспортных
  сбоев (когда HTTP-ответ не получен вовсе: DNS/connect/EOF/timeout) с
  экспоненциальным backoff и джиттером; каждый ретрай через ротационный прокси
  попадает на свежий exit-IP. Реальные HTTP-ответы (включая 4xx/5xx) не ретраятся.

```csharp
using var client = new TlsClientChromeHttpClient(new ChromeHttpClientOptions
{
    Proxy          = "http://user:pass@gate.provider.com:8000",
    RotatingProxy  = true,   // → DisableConnectionReuse включается автоматически
    MaxRetries     = 3,      // дополнительная устойчивость к редким EOF
    MaxConcurrency = 500,    // не перегружать прокси-гейт при массовом фан-ауте
});
```

> Если транспортный сбой не удалось устранить за `MaxRetries` попыток, запрос
> бросает `HttpRequestException` (как обычный `HttpClient`), а не возвращает
> «пустой» ответ со статусом 0. Оборачивайте вызовы в `try/catch` —
> см. `ExecuteShortWEBRequestAsync` в примере.

#### Горячая замена прокси

Прокси можно менять **на лету**, не пересоздавая клиент и сохраняя куки-jar
сессии (нативный слой перенаправляет транспорт сессии на новый адрес):

```csharp
client.SetProxy("http://user:pass@host:port");     // следующий запрос пойдёт через новый прокси
client.SetProxy("socks5://host:1080", rotating: true); // заодно пометить как ротационный
client.SetProxy(null);                               // вернуться к прямому соединению
var current = client.Proxy;                          // текущий прокси (null = напрямую)
```

Вызов потокобезопасен (можно дёргать при активных запросах) и применяется со
следующего запроса. Невалидный URL (не абсолютный URI) бросает
`ArgumentException`. Полезно для ручной ротации пула прокси, переключения
региона или быстрого ухода с забаненного IP.

## Структура

```
client/                       исходник клиента
  native/                     Go cffi-обёртка + скрипты сборки (.so/.dll)
  JAHTTPClient/
    Native/                   P/Invoke ([LibraryImport]) + resolver по RID
    Interop/                  JSON DTO (System.Text.Json source-gen)
    Fingerprinting/           Ja3Preset + профили (Chrome 148 = chrome_133 + UA 148)
    Cookies/                  ChromeCookieContainer
    ChromeHttpClient*.cs      абстракция + реализация
    runtimes/<rid>/native/    готовые бинарники движка (linux-x64, win-x64)
sniffer/                      снифер JASniffer (Core / Proxy / Web / Tests)
```

## Обновление под новый Chrome

Смените `TlsIdentifier` (например `"chrome_146"` — самый свежий в v1.14.0) и
User-Agent в профиле. Managed-код не меняется.
