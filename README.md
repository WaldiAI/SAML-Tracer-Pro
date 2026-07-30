# SAML Tracer Pro

Rozszerzenie Chrome (Manifest V3) do debugowania SSO: przechwytuje ruch, dekoduje `SAMLRequest` / `SAMLResponse` w locie, pokazuje atrybuty po nazwach przyjaznych, ma widok wszystkich żądań, widok błędów i dekoder JWT. Wszystko działa lokalnie — rozszerzenie nie wysyła nic na zewnątrz.

Rozpoznawanie działa **na poziomie protokołu, nie dostawcy** — nie ma w kodzie niczego zaszytego pod konkretny IdP. Szczegóły w sekcji [Zgodność z dostawcami](#zgodność-z-dostawcami-iam).

## Instalacja (tryb developerski)

1. Rozpakuj archiwum, np. do `~/saml-tracer-pro`.
2. Otwórz `chrome://extensions`.
3. Włącz **Developer mode** (prawy górny róg).
4. **Load unpacked** → wskaż katalog z plikiem `manifest.json`.
5. Przypnij ikonę do paska narzędzi.

Aktualizacja po edycji plików: **Reload** na kafelku rozszerzenia (przy zmianach w `panel/` wystarczy zamknąć i otworzyć okno tracera).

## Dwa sposoby użycia

| Sposób | Jak otworzyć | Kiedy |
| --- | --- | --- |
| Osobne okno | klik w ikonę na pasku | logowanie przenosi Cię między domenami, chcesz mieć tracer obok okna przeglądarki |
| Panel DevTools | F12 → zakładka **SAML** | debugujesz razem z Network / Console |

## Cykl nagrywania

Domyślnie rozszerzenie **nie nasłuchuje**. Jedna sesja debugowania wygląda tak:

1. **Start capture** (przycisk w pasku albo `Ctrl/Cmd+Enter`) — dopiero teraz cokolwiek jest przechwytywane.
2. Uruchamiasz logowanie. Kolejność ma znaczenie: startujesz **przed** kliknięciem, inaczej tracisz `AuthnRequest`, czyli początek flow.
3. Rozszerzenie zatrzymuje się samo, gdy rozmowa SAML **ucichnie** — domyślnie 15 s bez nowej wiadomości SAML i bez nawigacji w toku.
4. Przechwycone dane zostają w panelu do momentu, gdy klikniesz `Clear`. Pasek stanu mówi, dlaczego nagrywanie się skończyło, i oferuje „Start again".

Dlaczego cisza, a nie „stop po odebraniu `SAMLResponse`": zaraz po asercji dzieje się to, co często jest właśnie usterką — SP zakłada sesję i przekierowuje, odbija w pętli z powrotem do IdP albo zwraca 500. Zatrzymanie w sekundzie odebrania asercji obcięłoby najciekawszy fragment. Okno ciszy zostawia ten ogon w nagraniu, a jednocześnie kończy sesję po kilkunastu sekundach.

Dodatkowe zabezpieczenia:

- **Twardy limit czasu** (domyślnie 5 min). Jeśli logowanie padnie po stronie IdP, `SAMLResponse` nigdy nie przyjdzie i warunek ciszy sam z siebie by nie zadziałał.
- **Zawieszona nawigacja nie blokuje stopu** — żądanie `main_frame`, które nie kończy się w 20 s, przestaje być brane pod uwagę.
- **Ikona na pasku pokazuje `REC`** na czerwono, gdy nasłuch jest aktywny. Nie da się przypadkiem zostawić włączonego nagrywania bez śladu.

W ustawieniach można wrócić do trybu **Always on** (nasłuch od startu przeglądarki, także przy zamkniętym panelu) — wtedy panel otwierasz po fakcie i widzisz ostatnie wiadomości z bufora `chrome.storage.session`. To tryb wygodniejszy, ale zbierający znacznie więcej danych.

## Zakładki

- **SAML** — tylko wiadomości SAML. Nagłówek: URL, Issuer, Destination, Subject, Status, Issued, Encoding. Dalej: plakietki (podpis odpowiedzi / asercji, szyfrowanie, binding), pasek ważności, tabela atrybutów (Friendly / Name / Value), Conditions, Authentication, Signature z odciskiem certyfikatu, Parameters, nagłówki żądania i odpowiedzi, na końcu rozwijany **Raw XML** z kolorowaniem składni.
- **All Traffic** — wszystkie żądania z metodą, statusem, typem, czasem, przekierowaniem, treścią POST i nagłówkami. Każdy hop przekierowania to osobny wiersz.
- **Errors** — tylko 4xx, 5xx i błędy sieciowe (`net::ERR_*`).
- **Flow** — przechwycone logowanie odtworzone etapami jako oś czasu: start w aplikacji → `AuthnRequest` → uwierzytelnienie w IdP → asercja → konsumpcja na ACS → sesja aplikacji (analogicznie WS-Fed i logout). Każdy etap ma opis prostym językiem (co się dzieje, kto z kim rozmawia) i rozwijaną listę „What to check at this stage". Nad osią: pasek aktorów Browser ⇄ IdP ⇄ SP z rozpoznanymi hostami oraz **automatyczne diagnozy** — flow zatrzymany w IdP, asercja odrzucona przez SP (z numerem statusu), pętla przekierowań, flow inicjowany po stronie IdP, binding artifact, a także **odrzucenie asercji przez SP mimo czystych statusów HTTP** — wiele aplikacji (np. Salesforce) odpowiada na nieudaną walidację przekierowaniem 302 na własną stronę błędu z kodem 200; Flow rozpoznaje takie strony po ścieżce (`SamlError`, `SAMLValidationPage`, `sso-error`, `errorcode=`...), oznacza etap „The SP rejected the assertion” i podpowiada najczęstszą przyczynę: użytkownik nieutworzony po stronie SP albo NameID niepasujący do żadnego konta. Klik w dowolny hop przenosi do jego szczegółów. Zakładka służy jednocześnie jako samouczek SAML dla kogoś, kto widzi protokół pierwszy raz — pusta pokazuje opis, jak logowanie będzie wyglądać.
- **JWT** — wklej token (albo kliknij token wyłapany z nagłówka `Authorization` w ruchu): header, payload, signature, panel Highlights z iss / aud / exp i informacją, czy token wygasł.

Filtr nad listą szuka po URL, metodzie i statusie — wiele słów działa jak AND (`post 500 acs`).

Skróty: `Ctrl/Cmd+Enter` start/stop nagrywania, `1`–`5` zakładki, `↑`/`↓` lub `j`/`k` wybór wiersza, `/` lub `Ctrl/Cmd+F` filtr.

## Czego nie ma w oryginale

- **Pasek ważności asercji** — `NotBefore` → `NotOnOrAfter` z markerem „teraz”, licznikiem czasu do wygaśnięcia i podpowiedzią o przesunięciu zegara, gdy asercja jeszcze nie obowiązuje. To najczęstsza przyczyna „logowanie działa u mnie, nie działa u klienta”.
- **Import HAR** — poza formatem JSON saml-tracera wczytuje też HAR z DevTools i luźne tablice żądań. Importer jest tolerancyjny: mapuje `request`/`response`, nagłówki jako tablicę lub obiekt, `postData` jako tekst lub `params`, i sam wykrywa SAML w URL-u oraz w ciele POST.
- **Odcisk certyfikatu** — SHA-256 certyfikatu z `<ds:X509Certificate>` plus kopiowanie go jako PEM. Porównujesz z certyfikatem w aplikacji w Okcie bez wychodzenia z panelu.
- **Wykrywanie JWT w ruchu** — tokeny z nagłówków i ciał żądań są zbierane i dostępne jednym kliknięciem w zakładce JWT.
- **Pasek przypiętych pól** z rozszerzoną składnią (`path[n]`, `query:nazwa`, `saml:attr:email`).
- **Copy jako tekst** — cały wpis (podsumowanie + atrybuty + nagłówki + XML) w formie gotowej do wklejenia w ticket.
- Praca w osobnym oknie, nie tylko w DevTools.

## Ustawienia (ikona koła zębatego)

- **Highlighted domains** — po jednym hoście w linii, wildcardy dozwolone (`*.okta.com`, `sp.samltest.*`). Trafione wiersze dostają złotą gwiazdkę. Wpisanie samej domeny (`okta.com`) obejmuje też subdomeny.
- **Pinned fields** — pola pokazywane w pasku nad każdym wpisem:
  - nazwa nagłówka, np. `Set-Cookie` (najpierw szukane w odpowiedzi, potem w żądaniu),
  - `saml:issuer`, `saml:destination`, `saml:subject`, `saml:status`, `saml:audience`, `saml:notbefore`, `saml:notonorafter`, `saml:sessionindex`, `saml:inresponseto`, `saml:relaystate`, `saml:binding`, `saml:nameidformat`,
  - `saml:attr:email` — konkretny atrybut po nazwie przyjaznej albo pełnej,
  - `path[2]` / `path[-1]` — segment ścieżki URL (wyciąganie ID tenanta lub aplikacji),
  - `query:RelayState`, `url`, `host`, `status`.
  Przycisk pinezki przy każdym nagłówku, atrybucie i polu podsumowania dodaje wpis tutaj automatycznie.
- **Capture** — `Only when I start it` (domyślnie) albo `Always on`.
- **Stop after quiet** — długość okna ciszy kończącego sesję (5–60 s).
- **Hard time limit** — górna granica jednej sesji nagrywania (1 min – bez limitu).
- **Stop capturing by itself once the SAML flow goes quiet** — wyłączenie zostawia nagrywanie do ręcznego stopu (twardy limit nadal obowiązuje).
- **Capture only these domains** — biała lista hostów, które w ogóle są przechwytywane (wildcardy dozwolone). Puste = cały ruch. Wpisanie tu IdP i SP to najmocniejsza minimalizacja: ruch spoza listy nie trafia nawet do pamięci.
- **Remove Cookie and Authorization headers…** — domyślnie włączone. Eksport JSON, raport HTML i „Copy" zamieniają wartości nagłówków `Cookie`, `Set-Cookie`, `Authorization`, `Proxy-Authorization`, `X-Api-Key`, `X-CSRF-Token` i `DPoP` na `[redacted by SAML Tracer Pro]`. Nazwy nagłówków zostają, żeby było widać, co tam było. W panelu widzisz pełne wartości — redakcja dotyczy tylko tego, co opuszcza narzędzie.
- **In always-on mode, keep capturing while no tracer window is open** — dotyczy tylko trybu Always on.
- **Theme** — ciemny, jasny lub zgodnie z przeglądarką (w DevTools zgodnie z motywem DevTools).
- **Keep at most** — limit przechowywanych żądań.

## Zgodność z dostawcami IAM

Wykrywanie opiera się na nazwach parametrów z bindingów SAML 2.0 (`SAMLRequest`, `SAMLResponse`, `SAMLart`) i WS-Federation (`wa=wsignin1.0`, `wresult`), a parser jest **niezależny od prefiksów namespace** — `saml2:`, `saml:`, `ns2:`, `t:` albo brak prefiksu są traktowane identycznie. W kodzie nie ma nazwy żadnego dostawcy poza przykładami w komentarzach.

| Protokół / dostawca | Status | Uwagi |
| --- | --- | --- |
| SAML 2.0 — Okta, Entra ID (Azure AD), Ping, Keycloak, Shibboleth, Auth0, OneLogin, JumpCloud, Google Workspace, Salesforce jako IdP | pełne wsparcie | oba bindingi (POST i Redirect), `AuthnRequest`, `Response`, `LogoutRequest`/`LogoutResponse` |
| SAML 1.1 (starsze ADFS, legacy SSO) | pełne wsparcie | `NameIdentifier`, `AuthenticationStatement`, `AudienceRestrictionCondition`, `AttributeName` + `AttributeNamespace`, status jako QName (`samlp:Success`) |
| WS-Federation — ADFS i pochodne | pełne wsparcie | `wsignin1.0` / `wsignout1.0` z parametrami `wtrealm`, `wctx`, `wreply`, `whr`; token `wresult` jako czysty XML (bez base64), sekcja „WS-Federation envelope" z `AppliesTo`, `TokenType` i czasem życia |
| Binding Artifact (`SAMLart`) | wykrywany, nie dekodowany | asercję pobiera SP kanałem back-channel (SOAP), przeglądarka jej nie widzi — panel mówi to wprost zamiast pokazywać błąd dekodowania |
| Zaszyfrowane asercje (`EncryptedAssertion`) | wykrywane, nie odszyfrowywane | odszyfrowanie wymaga klucza prywatnego SP; panel pokazuje plakietkę „Encrypted assertion" |
| OIDC / OAuth 2.0 — Entra ID, Auth0, Keycloak, Okta | częściowo | żądania i odpowiedzi widoczne w **All Traffic**, tokeny `Bearer` i `id_token` z nagłówków i ciał wyłapywane do zakładki JWT. Nie ma dedykowanego widoku flow OIDC. Uwaga na ograniczenie przeglądarki: fragment URL (`#id_token=…` we flow implicit) nie jest wysyłany na serwer, więc nie pojawia się w `webRequest` |
| WS-Trust (SOAP), CAS, Kerberos/SPNEGO | brak | inne protokoły, nie ma parsera |

Nazwy atrybutów są tłumaczone na czytelne etykiety dla schematów `schemas.xmlsoap.org` (ADFS, Entra ID), `schemas.microsoft.com` oraz `urn:oid:` (Shibboleth / eduPerson). Jeśli IdP wysyła `FriendlyName`, ma pierwszeństwo; jeśli nie — etykieta jest wyprowadzana z nazwy.

Testy obejmują prawdziwe kształty odpowiedzi z Entra ID (bez prefiksów namespace), ADFS przez WS-Fed z asercją SAML 1.1 w kopercie WS-Trust, Shibbolethu (`urn:oid` + `FriendlyName`), błędu Ping/Keycloak z zagnieżdżonym `StatusCode` oraz legacy SAML 1.1.

## Diagnostyka — na co patrzeć

| Objaw | Gdzie sprawdzić |
| --- | --- |
| SP zwraca 400/500 na `/acs` | zakładka Errors, potem ten sam wpis w SAML — Status i Conditions |
| „Audience mismatch” | Conditions → Audience vs Audience URI / SP Entity ID (w ADFS: `AppliesTo` w kopercie WS-Fed) |
| „Assertion not yet valid” | pasek ważności — jeśli marker „teraz” jest przed początkiem okna, zegary SP i IdP się rozjeżdżają |
| SP nie widzi grup/atrybutów | tabela Attributes — atrybut bez wartości ma `(no values)`, czyli mapowanie po stronie IdP zwróciło pustkę |
| „InResponseTo mismatch” | `InResponseTo` w odpowiedzi vs `ID` w `AuthnRequest` (poprzedni hop w All Traffic) |
| Podpis odrzucony | plakietki (co jest podpisane: odpowiedź, asercja, oba) + odcisk certyfikatu w sekcji Signature |
| ADFS: „token not valid” | sekcja WS-Federation envelope — `AppliesTo` vs identyfikator RP, `Created`/`Expires` vs zegar SP |
| Pętla przekierowań | All Traffic — każdy hop 302 osobno, z nagłówkiem `Location` |

## Eksport i raport

- **Export JSON** (ikona ze strzałką w dół) — zapisuje aktualnie widoczne wpisy (czyli filtr i zakładka mają znaczenie). Każdy wpis ma zarówno pola natywne, jak i aliasy `postData` / `timestamp`, więc plik czyta się też innymi narzędziami.
- **Import** (strzałka w górę lub przeciągnięcie pliku w okno) — JSON z tego rozszerzenia, JSON saml-tracera, HAR.
- **Raport HTML** (ikona dokumentu) — jeden samodzielny plik: statystyki, karty wiadomości SAML z atrybutami i XML-em, lista błędów, tabela całego ruchu. Nadaje się do wysłania do supportu i do druku.

## Bezpieczeństwo i dane osobowe

### Co wychodzi z maszyny

Nic. Rozszerzenie nie ma ani jednego wywołania sieciowego: brak `fetch`, `XMLHttpRequest`, `WebSocket`, `sendBeacon`, brak telemetrii, brak zewnętrznych skryptów, fontów, CDN-ów i obrazków. Cały kod (parser SAML, dekoder JWT, generator raportu) jest lokalny, czcionki są systemowe. Manifest V3 dodatkowo blokuje wykonanie zdalnego kodu. Można to sprawdzić jednym poleceniem w katalogu rozszerzenia:

```bash
grep -rnE "fetch\(|XMLHttpRequest|WebSocket|sendBeacon|https?://" --include=*.js --include=*.html --include=*.css . | grep -v tests/
```

Jedyne dane opuszczające narzędzie to pliki, które **sam** zapiszesz (Export JSON, raport HTML, Save XML) i to, co skopiujesz do schowka.

### Gdzie i jak długo leżą dane

| Dane | Miejsce | Czas życia |
| --- | --- | --- |
| Przechwycone żądania, zakodowane `SAMLResponse`, nagłówki (w tym `Cookie`) | RAM service workera i otwartego panelu | do `Clear`, przeładowania rozszerzenia lub zamknięcia przeglądarki; zbierane tylko w trakcie uruchomionej sesji nagrywania |
| Bufor ostatnich ~150 wpisów | `chrome.storage.session` — **pamięć**, nie dysk | do zamknięcia przeglądarki; Chrome nie zapisuje tego obszaru na dysk |
| Zdekodowany XML i sparsowany model | RAM panelu | do zamknięcia panelu |
| Ustawienia (highlight, pinezki, biała lista, motyw) | `chrome.storage.local` | do odinstalowania rozszerzenia |
| Wklejony JWT | pole tekstowe w panelu | do wyczyszczenia pola / zamknięcia panelu |

**`storage.local`, nie `storage.sync`** — świadomie. Nazwy hostów IdP i SP oraz przypięte pola opisują systemy klienta, więc nie mają czego szukać w koncie Google i na serwerach synchronizacji. Jeśli używałeś wersji 1.0.x, przy pierwszym uruchomieniu 1.1.0 ustawienia są przenoszone do `storage.local`, a kopia z `sync` usuwana.

Rozszerzenie **nie prowadzi żadnego logu na dysku**, nie zapisuje asercji automatycznie i nie wysyła ich do siebie samego między sesjami.

### Uprawnienia i po co są

| Uprawnienie | Do czego |
| --- | --- |
| `webRequest` + `<all_urls>` | podglądanie metadanych żądań i ciał POST — bez tego nie ma tracera |
| `storage` | ustawienia (`local`) i bufor sesji (`session`) |
| `downloads` | zapis eksportu, raportu i XML-a |
| `clipboardRead` / `clipboardWrite` | przyciski „Copy" i „Paste from clipboard" w dekoderze JWT |
| `tabs` | otwarcie okna tracera |

Brak `scripting` i brak content scriptów — rozszerzenie nie wstrzykuje niczego na strony i nie czyta DOM-u odwiedzanych witryn.

### Konfiguracja zgodna z minimalizacją danych (RODO art. 5 ust. 1 lit. c)

Domyślnie nasłuch obejmuje cały ruch, także niezwiązany z SSO — wygodne, ale z perspektywy minimalizacji zbyt szerokie. Zalecane ustawienie na czas normalnej pracy:

1. **Capture: Only when I start it** (domyślnie) + auto-stop na ciszy. Nagranie trwa tyle, ile flow — kilkanaście sekund zamiast całego dnia. Nic nie musisz usuwać, bo nic się nie zebrało.
2. **Capture only these domains** → wpisz wyłącznie hosty IdP i SP, np. `*.okta.com` i `sp.samltest.kmmr.jp`. Wszystko poza listą nie jest w ogóle przechwytywane — bank, poczta i intranet nigdy nie trafiają do pamięci narzędzia. Te dwa mechanizmy działają niezależnie: pierwszy ogranicza **czas**, drugi **zakres**.
3. **Remove Cookie and Authorization headers…** → zostaw włączone, chyba że ticket wymaga właśnie ciasteczek sesyjnych.
4. `Clear` (kosz) po skończonej analizie — dane z nagrania żyją w panelu do wyczyszczenia.
5. Do testów używaj konta testowego, nie konta realnego użytkownika — asercja zawiera imię, nazwisko, adres e-mail i grupy, czyli dane osobowe.

### Praca z asercjami — o czym pamiętać

- Asercja SAML i JWT to **poświadczenia**, nie tylko dane. Ważna asercja wklejona w ticket może być odtworzona przez SP w okienku ważności (u Okty domyślnie 5 minut) — dlatego dołączaj raport dopiero po wygaśnięciu okna albo z konta testowego.
- Eksport, raport i skopiowany tekst zawierają pełne atrybuty (e-mail, grupy, dział) — traktuj pliki jak dane osobowe: przekazywanie zewnętrznemu supportowi to udostępnienie danych, więc obowiązuje umowa powierzenia / podstawa prawna, a plik po sprawie należy usunąć.
- Rozszerzenie **nie weryfikuje podpisów** — pokazuje algorytm i odcisk certyfikatu. Nie jest dowodem poprawności podpisu ani narzędziem audytu kryptograficznego.
- Nie ma szyfrowania eksportowanych plików. Jeśli mają wyjść poza Twoją maszynę, spakuj je z hasłem albo przekaż kanałem szyfrowanym.
- Rozszerzenie ładowane jako „unpacked" nie aktualizuje się samo i każdy z dostępem do Twojego profilu Chrome widzi te same dane w panelu — zwykłe zasady blokowania stacji obowiązują.

## Ograniczenia

- Chrome nie udostępnia rozszerzeniom **treści odpowiedzi** w `webRequest`, więc widać ciała żądań (tam jest `SAMLResponse` przy POST binding), ale nie HTML odpowiedzi. Do SAML wystarcza; do podglądu treści odpowiedzi zostaje zakładka Network.
- Ruch stron `chrome://`, Chrome Web Store i innych rozszerzeń jest niewidoczny dla rozszerzeń — to ograniczenie przeglądarki.
- Fragment URL (część po `#`) nie jest wysyłany na serwer, więc tokeny z flow implicit OIDC nie trafiają do `webRequest`. Wklej je ręcznie w zakładce JWT.
- Bufor po restarcie service workera obejmuje ostatnie ~150 wpisów (w pamięci, nie na dysku); pełna historia żyje w otwartym panelu.
- Bardzo duże asercje (>1,5 MB zakodowanego parametru) są obcinane — wpis dostaje wtedy plakietkę „Parameter truncated”.

## Struktura

```
manifest.json          uprawnienia, service worker, devtools_page, action
background.js          nasłuch webRequest, budowa wpisów, wykrywanie SAML, port do panelu
devtools/              rejestracja zakładki „SAML” w DevTools
panel/panel.html       układ: cztery zakładki, lista, panel szczegółów, dekoder JWT
panel/panel.css        tokeny kolorów i typografii, oba motywy
panel/panel.js         stan, render listy i szczegółów, import/eksport, raport, JWT
lib/saml.js            base64 + inflate, parser SAML, formatowanie i kolorowanie XML
lib/jwt.js             dekoder JWT
lib/util.js            dopasowywanie hostów, wykrywanie parametrów SAML, czas
lib/report.js          generator samodzielnego raportu HTML
tests/                 testy w Node (jsdom) — logika SAML/JWT, panel, service worker
```

## Testy

```bash
npm install jsdom
node tests/run.mjs         # dekodowanie, parser, formatowanie XML, JWT, raport
node tests/panel.mjs       # panel w jsdom: lista, szczegóły, filtr, import HAR, eksport
node tests/background.mjs  # pipeline webRequest: hopy, SAML, błędy, pauza, clear
```

Testy uruchamiają prawdziwy kod rozszerzenia na atrapach API Chrome, więc łapią błędy jeszcze przed przeładowaniem wtyczki.
