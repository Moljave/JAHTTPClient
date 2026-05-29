# JAHTTPClient

`HttpClient`-совместимый HTTP-клиент для **.NET 10 / C# 13**, который полностью
эмулирует **TLS (JA3/JA4)** и **HTTP/2** fingerprint **Google Chrome 148** и тем
самым проходит anti-bot системы (Akamai Bot Manager, Cloudflare), фильтрующие
запросы по ClientHello.

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
cd native
./build-windows.ps1
# → src/JAHTTPClient/runtimes/win-x64/native/tls-client-windows-64.dll
```

**Linux** (нужен gcc):

```bash
cd native
make linux
# → src/JAHTTPClient/runtimes/linux-x64/native/tls-client-linux-amd64.so
```

> Бинарь не коммитится в репозиторий (см. `.gitignore`) — он большой и
> платформозависимый. `dotnet build` копирует его рядом со сборкой автоматически.

### 2. Решение

```bash
dotnet build -c Release
dotnet run -c Release --project samples/JAHTTPClient.Sample
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
`ExecuteShortWEBRequestAsync` переносится почти без изменений — см.
`samples/JAHTTPClient.Sample/Program.cs`.

### Семантика `MaxAutomaticRedirections`

Редиректы обрабатываются в managed-коде, поэтому можно вернуть **промежуточный**
ответ. Для цепочки `авторизация → проверка → финиш`:

| Значение | Результат |
|---|---|
| `10` (по умолч.) | ответ последнего шага («финиш») |
| `1` | контент и заголовки шага «проверка» |
| `AllowAutoRedirect = false` | первый `3xx` как есть |

Куки между хопами переносятся автоматически (один нативный jar на сессию).

### Куки

- Серверные куки (`_abck`, `ak_bmsc`, `bm_sz`, `cf_clearance`) персистятся
  автоматически в нативном jar на время жизни клиента.
- Пользовательские куки: `client.Cookies.SetCookie(...)`,
  `client.Cookies.AddRaw(url, "a=1; b=2")`, `client.Cookies.Import(url, cookieContainer)`.
  При совпадении имени пользовательская кука перекрывает серверную.
- Чтение: `client.Cookies.GetCookies(url)`.

### Многопоточность и прокси

Нативный слой делает реальный async I/O, поэтому один клиент тянет тысячи
параллельных запросов. Каждый ответ освобождается (`freeMemory`), каждая сессия
закрывается на `Dispose` (`destroySession`) — без утечек. Прокси задаётся в
опциях (`Proxy`, `RotatingProxy`). При экстремальном фан-ауте можно ограничить
число одновременных запросов через `MaxConcurrency` (по умолчанию без лимита).

## Структура

```
native/                       Go cffi-обёртка + скрипты сборки
src/JAHTTPClient/
  Native/                     P/Invoke ([LibraryImport]) + resolver по RID
  Interop/                    JSON DTO (System.Text.Json source-gen)
  Fingerprinting/             Ja3Preset + профили (Chrome 148 = chrome_133 + UA 148)
  Cookies/                    ChromeCookieContainer
  ChromeHttpClient*.cs        абстракция + реализация
samples/JAHTTPClient.Sample/  пример + миграция ExecuteShortWEBRequestAsync
```

## Обновление под новый Chrome

Смените `TlsIdentifier` (например `"chrome_146"` — самый свежий в v1.14.0) и
User-Agent в профиле. Managed-код не меняется.
