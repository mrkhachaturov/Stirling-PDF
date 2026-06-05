# AstraPDF — план патчей подписи (decision record)

> Внутренний документ AstraTeam. Не апстримовский. Цель — зафиксировать **что мы решили
> сделать**, чтобы не было путаницы перед реализацией. Читается перед началом работ.
> Связанные доки: `USERCERT_ISSUER.md` (наша фича issuer'а), `CLAUDE.local.md` (handoff).
> Апстримовские (НЕ наши): `SHARED_SIGNING.md`, `docs/.../Certificate-Signing.md`,
> `docs/.../Shared-Signing.md`.

---

## 0. Цель форка (зачем вообще трогаем репозиторий)

Чтобы каждый пользователь подписывал PDF **своим персональным сертификатом**, выписанным
нашим **step-ca** (цепочка `leaf → AstraTeam Document Signing CA → Root G2`), а не
самоподписанным. Плюс — чтобы подписи были **долгоживущими** (TSA + LTV) и доступными в
**обычном** инструменте подписи, а не только в коллаборативном shared-signing.

Мы намеренно меняем поведение апстрима под себя. «У апстрима так не сделано» — не аргумент:
ради этого и существует форк.

---

## Статус реализации (2026-06-05)

Сделано в коде форка (ветка `feat/user-cert-external-issuer`), backend полностью собран и
протестирован (`:proprietary:test` + spotless PASS), фронт typecheck чист по изменённым файлам:

- **Patch 1 (bytea)** — ✅ ранее, в образе.
- **Patch 2 backend** — ✅ seam `UserCertificateServiceInterface` (common) ← `UserServerCertificateService`
  (proprietary, username-keyed); `CertSignController` инжектит seam + `UserServiceInterface`, новая ветка
  `case "USER_CERT"`; флаг **`system.userCertificate.enabled`** (`UserCertificateSettings`); ConfigController
  отдаёт **`userCertificateEnabled`**.
- **Patch 2 frontend** — ✅ `userCertificateEnabled` в `appConfig`; гейт «Auto» = server||user; в AUTO
  шлётся `certType=USER_CERT` когда personal; лейбл «Auto (personal)»; tooltip `autoPersonal.*` (en-GB+ru-RU);
  `useSignModeTips` config-aware.
- **Patch 3 (TSA)** — ✅ **B-T (signature timestamp)**: choke-point — `CertSignController.sign()` (общий для
  standalone и shared-finalize через `PdfSigningService`). Флаг **`security.timestamp.signingEnabled`**
  (default false); при true `createSignature.setTsaUrl(defaultTsaUrl)` → PDFBox `ValidationTimeStamp`
  встраивает RFC-3161 timestamp. Применяется и в `PdfSigningServiceImpl` (shared). DigiCert — дефолт.
  - **DSS/LTV (B-LT) — follow-up.** Готового хелпера в PDFBox нет; offline-LTV (вшить цепочку+CRL в DSS +
    doc-timestamp) — отдельная задача. B-T уже держит подпись валидной после истечения серта, пока валидатор
    строит/доверяет цепочке (Root G2) и TSA; CRL лист тянет по CDP (`http://crl.astrateam.net/1.0/crl`).

### Доставка изменилась: jar-overlay ❌ → полная fat-сборка из форка ✅

Тронут фронт → jar-overlay (только proprietary jar поверх официального fat-образа) **больше не годится**.
Сверх того: официальный `stirlingtools/stirling-pdf:2.11.0-fat` бандл **вообще не содержит Shared-Signing UI**
(подтверждено пробой живого бандла в `SHARED-SIGNING-STATUS.md`). Наш форк-исходник (v2.11.0) Shared-Signing
фронт **содержит** (`frontend/src/core/components/shared/signing/SignPopout.tsx`, `useGroupSigningEnabled`,
`QuickAccessBar.tsx`), просто в старой раскладке (`frontend/src/`, а не `frontend/editor/src/` как в main).
→ **Из main собирать не нужно.** Dockerfile в `astrateam-net/containers` переключается на полный
`docker/embedded/Dockerfile.fat` из форк-тега `astrapdf-2.11.0` — это даёт и Shared-Signing UI, и наш фронт.

### Новые env для astrapdf compose (добавить; существующие не трогать)

```yaml
SYSTEM_USERCERTIFICATE_ENABLED: "true"          # Patch 2: включает personal-режим "Auto"
SECURITY_TIMESTAMP_SIGNINGENABLED: "true"       # Patch 3: B-T timestamp (DigiCert дефолт)
SECURITY_VALIDATION_TRUST_USESYSTEMTRUST: "true"  # + Root G2 в Java-trust образа
SECURITY_VALIDATION_REVOCATION_MODE: "crl"
SECURITY_VALIDATION_REVOCATION_HARDFAIL: "false"
```

---

## 1. Терминология (источник всей путаницы — зафиксировать раз и навсегда)

В Stirling «server certificate» перегружено. Три разных сущности:

| Внутр. `certType` | Бэкенд-класс | Подпись в UI (collab) | В апстрим-доке | Наше? |
|---|---|---|---|---|
| `SERVER` | `ServerCertificateService` | **Organization Certificate** | **Server / Organization** | НЕТ (один общий серт на инстанс) |
| `USER_CERT` | `UserServerCertificateService` | **Personal Certificate** | не описан | **ДА — step-ca per-user** |
| `PKCS12/PEM/JKS` | — (загрузка файла) | Custom Certificate | Custom | НЕТ |

Две точки входа подписи:
- **Standalone-инструмент «Certificate Sign»** → `CertSignController` (`/api/v1/security/cert-sign`).
  Режимы в UI: `Manual` (загрузка файла) / `Auto (server)` (= `SERVER`). **`USER_CERT` тут НЕ доступен.**
- **Shared-signing / sign-request** → `SigningSessionController` → `SigningFinalizationService`.
  Участник выбирает `SERVER` / `USER_CERT` / загрузку. **`USER_CERT` доступен только здесь.**

Ключевой архитектурный факт: **вся криптоподпись идёт через `CertSignController.sign()`** —
и standalone, и shared-finalize (последний через `PdfSigningService.signWithKeystore` →
`CertSignController.sign`). Одна точка врезки покрывает оба пути.

Как устроен пароль per-user keystore: генерится сервером детерминированно
(`"stirling-user-cert-" + userId`), хранится в БД зашифрованным (`MetadataEncryptionService`),
пользователь его НЕ вводит. → в per-user/Auto режиме поле пароля в UI не нужно.

---

## 2. Уже сделано

### Patch 1 — bytea persistence fix ✅ (закоммичен, задеплоен)
- Проблема: `@Lob byte[]` на колонке `keystore_data` (и `StoredFileBlob.data`) на PostgreSQL
  биндился как Large Object (OID/bigint) → INSERT падал `42804: bytea but expression is bigint`.
  Баг апстримовский (есть в v2.11.0 и в их main), маскируется на H2 (их дефолт). Наш step-ca
  первым реально дошёл до сохранения на Postgres и вскрыл его.
- Фикс: `@Lob` → `@JdbcTypeCode(SqlTypes.VARBINARY)` в `UserServerCertificateEntity` и
  `StoredFileBlob`. Колонки уже `bytea` → миграций нет.
- Коммит `553fae31c`, тег форка `astrapdf-2.11.0` переставлен на него, образ собран CI:
  `ghcr.io/astrateam-net/astrapdf:2.11.0@sha256:1442623583b990d29bf109d827da15367196edce05705f0c43d47d7191cb503a`.

---

## 3. Патчи к реализации (что делаем)

### Patch 2 — «Auto = настроенный механизм»: per-user в standalone-инструменте

**Идея.** Кнопка «Auto» должна подписывать тем механизмом, который настроен на инстансе.
Три взаимоисключающих режима managed-подписи (одновременно нельзя — выбирается один):
1. **server self-signed** — Stirling сам генерит один самоподписанный серт на инстанс (текущий дефолт);
2. **organization** — общий серт из файла `configs/keystore.p12`;
3. **per-user (наш, step-ca)** — каждому свой нормальный серт через нашу логику.

(1) и (2) — это одна ветка `ServerCertificateService`, переключаемая `system.serverCertificate.enabled`.
(3) — новая ветка, которую надо подключить к «Auto» в standalone-инструменте.

«Manual / Custom» (загрузить свой `.p12`) остаётся как есть — отдельно от «Auto».

**Что меняем:**
- **Backend `CertSignController`:** заинжектить `userServerCertificateService` (proprietary, optional);
  добавить ветку `USER_CERT` (взять аутентифицированного юзера → `getOrCreateUserCertificate` +
  `getUserKeyStore` + `getUserKeystorePassword`, как в `SigningFinalizationService` строки 870–940);
  требует логина → понятная 400 без юзера. Пароль не спрашиваем.
- **Конфиг (`UserCertificateSettings`):** новый `system.userCertificate.enabled` (bool). `true` →
  managed-механизм для «Auto» = per-user, имеет приоритет над server-веткой. (`issuer=selfsigned|stepca`
  остаётся — это *как* выписывать, не *где* предлагать.)
- **Config → фронт (`ConfigController`):** отдавать `userCertificateEnabled` (сейчас отдаётся только
  `serverCertificateEnabled` и `runningProOrHigher`).
- **Frontend (`certSign`):** когда `userCertificateEnabled` — «Auto» шлёт `certType=USER_CERT` вместо
  `SERVER`; осмысленная подпись кнопки (напр. «Auto (personal)»); поле пароля скрыто.
- **Frontend — ослабить гейт кнопки «Auto» (`CertificateTypeSettings.tsx`).** Сейчас кнопка «Auto»
  показывается **только** при `serverCertificateEnabled` (строки 17, 20, 53) и сбрасывает режим в
  `MANUAL`, если server cert выключен. → Изменить условие на
  **`serverCertificateEnabled || userCertificateEnabled`**, иначе в нашем случае (server off, user on)
  кнопки «Auto» вообще нет. Это и есть «должно срабатывать и от user-сертификата».
- **Frontend — текст подсказки «Auto» должен меняться в per-user режиме.** Подсказка «О PDF-подписях»
  (`certSign.signMode.tooltip.auto.*` в `frontend/public/locales/en-GB/translation.toml`) сейчас
  описывает **серверный self-signed**:
  > *title:* «Auto - Zero-setup, instant system seal»
  > *text:* «Signs with a server **self-signed** certificate … typically shows **Unverified** in viewers.»

  Для нашего режима (`userCertificate.enabled`, выписка step-ca — НЕ organization и НЕ self-signed)
  это **неверно**: подписывается **персональный** серт пользователя из нашего CA (chain → Root G2),
  per-person identity, и в просмотрщике он **Доверенный** (Trusted), а не Unverified; с Patch 3 ещё и
  timestamped → бессрочно валиден (LTV). → Подсказка «Auto» должна быть **условной**: когда активен
  per-user режим — отдельный набор ключей (напр. `certSign.signMode.tooltip.autoPersonal.*`) с текстом
  про персональный CA-серт, доверенный, долгоживущий; иначе — текущий текст про server self-signed.
- **Переводы новых ключей — в `en-GB` И `ru-RU` обязательно.** `en-GB` — источник (правило проекта:
  `en-GB`, не `en-US`). Но наш дефолтный locale — **`ru-RU`** (`SYSTEM_DEFAULTLOCALE: ru-RU`), и
  существующий блок `[certSign.signMode.tooltip.auto]` уже переведён в
  `frontend/public/locales/ru-RU/translation.toml`. → Любые новые ключи (`autoPersonal.*` и пр.) надо
  добавлять **и в `en-GB`, и в `ru-RU`**, иначе у нас в UI будет английский фолбэк. (Остальные locale
  при желании — но это минимум.)
- **Shared-путь** уже умеет `USER_CERT` — не трогаем.

**Важно про serverCertificate как «prerequisite».** Жёсткого гейта нет: `ensureSigningEnabled()`
(`WorkflowSessionService:66`) проверяет только `storage.enabled` + `storage.signing.enabled`.
`SYSTEM_SERVERCERTIFICATE_ENABLED=true` из апстрим-доки нужен лишь для (а) опции `SERVER` и
(б) серверного trust-anchor — **не** для самой shared-подписи. Опция «Personal Certificate» в shared
гейтится `runningProOrHigher` (Pro), не серверным сертом. → **с `userCertificate.enabled=true` можно
выключить `SYSTEM_SERVERCERTIFICATE_ENABLED`** и подписывать только персональными step-ca сертами.
Единственная правка, которую это требует на фронте — гейт кнопки «Auto» выше.

### Patch 3 — TSA + LTV автоматически в пути подписи (по сути — приоритет №1)

**Зачем.** Листья step-ca короткие (90 дней). Без RFC-3161 timestamp подпись после истечения
серта становится «validity unknown». Штамп фиксирует «подписано, пока серт был жив» → подпись
валидна бессрочно (LTV). Требует, чтобы корень TSA был доверенным у проверяющего.

**Точка врезки.** `CertSignController.sign()` (общий choke-point для standalone и shared-finalize).
Сейчас он НЕ ставит timestamp и НЕ вшивает LTV. `TimestampController` существует, но это
ОТДЕЛЬНЫЙ standalone-инструмент `/timestamp-pdf`, в путь подписи не вызывается.

**Что добавляем в `CertSignController.sign()` (→ автоматически и для per-user, и для всех):**
1. **RFC-3161 timestamp** в CMS-подпись, TSA из `security.timestamp.defaultTsaUrl`.
2. **LTV/DSS:** вшить в PDF validation data — полную цепочку + CRL (лист несёт
   `crlDistributionPoints → http://crl.astrateam.net/1.0/crl`).
- Управление: флаг (напр. `security.timestamp.signingEnabled` или наличие defaultTsaUrl).
- **TSA:** primary — **DigiCert** (уже дефолт `security.timestamp.defaultTsaUrl =
  http://timestamp.digicert.com`, доступность с swarm подтверждена, корень в Adobe AATL + Windows).
  Fallback — **Sectigo** (`http://timestamp.sectigo.com`, тоже AATL). MeSign — под вопросом,
  пока не используем.
- Пресеты живут хардкодом в `TimestampController.TSA_PRESETS` (DigiCert, Sectigo, SSL.com,
  FreeTSA, MeSign); кастомные — `security.timestamp.customTsaUrls`.

---

## 4. Деплой-конфиг astrapdf (validation/trust) — env, без пересборки образа

Сейчас в `stacks/tools/astrapdf/docker-compose.yml` настроена только **выписка**
(`SYSTEM_USERCERTIFICATE_*`), а сторона **валидации** пуста. Чтобы встроенный валидатор Stirling
тоже показывал подписи доверенными (внешние Adobe/Windows и так доверяют Root G2 из AD):

```yaml
# доверять нашей цепочке через системный trust (+ Root G2 в Java-trust контейнера)
SECURITY_VALIDATION_TRUST_USESYSTEMTRUST: "true"
# отзыв через CRL нашего step-ca (OCSP у step-ca нет), не падать при недоступности
SECURITY_VALIDATION_REVOCATION_MODE: "crl"
SECURITY_VALIDATION_REVOCATION_HARDFAIL: "false"
# TSA по умолчанию (DigiCert уже дефолт; Sectigo — в customTsaUrls)
# SECURITY_TIMESTAMP_DEFAULTTSAURL: "http://timestamp.digicert.com"
```
Плюс занести **Root G2** в Java-trust образа (OS `update-ca-certificates` или keytool в cacerts).
`serverAsAnchor` оставить `true` (нужен для опции SERVER; на нашу step-ca цепочку не влияет).

> Важно: `SYSTEM_USERCERTIFICATE_CABUNDLEPATH=/configs/root_ca.crt` — это ДРУГОЙ trust-контекст
> (только TLS-звонок в step-ca при выписке), к валидации подписей не применяется.

---

## 5. Приоритет

1. ✅ Patch 1 (bytea) — сделан.
2. **Patch 3 (TSA + LTV в `CertSignController.sign`)** — без него подписи временные. По сути главное.
3. **Patch 2 (Auto → USER_CERT)** — UX: персональная подпись в обычном инструменте.
4. **Env-конфиг (раздел 4)** — можно применить сразу в compose, параллельно.

---

## 6. Открытые вопросы / follow-up (не закрыты)

- **DSS/LTV (PAdES B-LT) — отдельный патч кода.** Сейчас сделан **B-T** (signature timestamp): подпись
  переживает истечение короткого step-ca листа. B-T тянет цепочку+CRL **онлайн в момент проверки** (лист
  несёт CDP `http://crl.astrateam.net/1.0/crl`) — валидно, пока наша PKI и CRL-эндпоинт доступны. **B-LT**
  вшивает validation data (полная цепочка + CRL) в **DSS-словарь самого PDF** при подписи → документ
  самодостаточен, проверяется офлайн и валиден, даже если CA/CRL когда-нибудь выключат (Acrobat: зелёный
  «LTV enabled»). Нужен, если документы должны проверяться годами / на внешней стороне / пережить вывод PKI.
  - Объём: в PDFBox готового хелпера нет — при подписи скачать CRL по CDP, собрать цепочку, сложить в DSS
    (`COSName.DSS` → Certs/CRLs), затем document-timestamp (для B-LTA — ещё archive-timestamp). Врезка — та же
    точка `CertSignController.sign()`, после наложения подписи.
  - Для внутреннего документооборота AstraTeam (PKI и CRL рядом, всегда доступны) **B-T часто достаточно** —
    отсюда приоритет: B-T сразу, B-LT по необходимости.
- **DocMDP / сертифицирующая подпись (lock документа) — запланировано, не реализовано.** Сейчас
  cert-sign ставит **approval**-подпись (`SUBFILTER_ADBE_PKCS7_DETACHED`, без DocMDP-трансформа):
  документ не блокируется, можно переподписать много раз, правки лишь делают подпись недействительной
  (детектируются постфактум, но не запрещаются). «Read-only после подписи», как в Adobe, даёт
  **сертифицирующая (DocMDP) подпись** — значение `/P`:
  - **P=1** «No changes» — полный read-only (ни форм, ни доп-подписей);
  - **P=2** «Form fill-in + signatures» — можно заполнять формы и до-подписывать, контент нельзя;
  - **P=3** — то же + аннотации/комментарии.
  Совместимый просмотрщик (Adobe) запрещённые изменения **блокирует заранее** и помечает документ
  сертифицированным. Ограничения: такая подпись только **одна** и обязательно **первая**; после P=1
  дальнейшее подписание невозможно → для мультиподписи берут P=2. Поэтому это **опт-ин**, дефолт —
  approval (текущее поведение).
  - Объём: бэкенд — флаг + уровень в `SignPDFWithCertRequest`; в `CertSignController.sign()` перед
    `addSignature` вызвать `SignUtils.setMDPPermission(doc, signature, p)` (PDFBox умеет) для первой
    подписи. Фронт — чекбокс «Сертифицировать/заблокировать» + выбор P1/P2/P3 в инструменте cert-sign.
    Врезка та же, что у остальных правок подписи.
- **Имя в name-constraints интермедиата** — обсуждение было прервано, вернуться. (DN-префикс
  `C=RU, L=Moscow, O=AstraTeam Ltd.` в `pdf-sign.tpl` — load-bearing, менять = пере-выпуск интермедиата.)
- **MeSign TSA** — проверить, доверен ли корень; до тех пор не используем.
- Подтвердить, что `CertSignController` в нашем деплое аутентифицирован (есть Principal) —
  per-user без юзера невозможен.
