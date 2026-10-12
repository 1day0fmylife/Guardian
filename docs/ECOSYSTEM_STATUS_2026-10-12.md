# Экосистема Arlan — статус реализации и сквозной приёмки (12.10.2026)

> Контрольный документ для Codex и владельцев шести репозиториев. Координатор: [Guardian #17](https://github.com/1day0fmylife/Guardian/issues/17). Исходная программа содержит 45 неизменных ID; нижеприведённые follow-up issues **не увеличивают** это количество. Сводка не заменяет исходные подробные постановки и не свидетельствует о выполненных автором документа тестах.

## Неизменяемая архитектурная граница

ArlanPhone в управляемом режиме обращается к SunkarDAV, **device-facing** Admiral и SunkarCWMP ACS только по разрешённой сети Guardian (WireGuard, приватный DNS/TLS, per-device grants/ACL, без прямого WAN fallback). Guardian — транспорт и граница устройства, но не хранилище DAV/ACS credentials, не административный API Admiral и не установщик firmware. CWMP agent остаётся отдельным непривилегированным компонентом; ACS NBI остаётся серверным интерфейсом. ArlanMeet/SIP/RTP должен оставаться независимым.

Отдельные уровни доказательств: `merged` ≠ `unit/local` ≠ `single exact-main multi-repo E2E` ≠ `installed pilot` ≠ `physical board`. Все отсутствующие результаты отмечаются BLOCKED/NOT RUN, не PASS.

## Проверенные головы main

| Репозиторий | SHA |
|---|---|
| Guardian | `c4dee184852e4d374f9608fc9139d1e479f84059` |
| ArlanPhone | `7d96673151a4e3edb853cc8aa9066567f64853ba` |
| Admiral | `64e7b011d49ff8a6b0e016a3745931455e50b04d` |
| SunkarCWMP | `b983144f9311340874625a37bcec5372e546c6bf` |
| SunkarDAV | `d62504666c8c3f5c07d77b168f38834ece72a33c` |
| ArlanMeet | `a8ff17f8b671e401e836543093f6d6e9c7122632` |

Это срез, а не постоянный pin — перед каждым Codex PR заново сверять upstream и изменившиеся зависимости.

## Раскладка исходных 45 ID

| Реализация слита: 26 | Частично: 7 | Остаток/отложено: 12 |
|---|---|---|
| G-01…G-08; A-01…A-05, A-07; M-01…M-03; C-01…C-04; D-01…D-05 | G-09; A-06, A-08; M-04; T-01; X-01, X-02 | A-09, A-10; M-05, M-06; C-05, C-06; T-02…T-06; X-03 |

C-03 [#41](https://github.com/1day0fmylife/SunkarCWMP/pull/41) и C-04 [#42](https://github.com/1day0fmylife/SunkarCWMP/pull/42) уже слиты. Локальный installed C-04 collector: 79/79, но независимого off-host key escrow/failure-domain нет, ACS pilot gate остаётся OPEN ([#19](https://github.com/1day0fmylife/SunkarCWMP/issues/19)). G-09 [#16](https://github.com/1day0fmylife/Guardian/pull/16) — только benchmark/readiness, не remote node-agent/HA. A-06 — защищённая подписанная загрузка/staging без install. A-08 [#134](https://github.com/1day0fmylife/ArlanPhone/pull/134) лишь durable RAUC intent/fenced retry: production physical A/B не закрыт.

Admiral M-04 [#17](https://github.com/1day0fmylife/Admiral/pull/17): reference deployment 65; **старый direct-host** QEMU full 40/40, resilience 54/14; **отдельный** kernel WG/private DNS/TLS gate 12; узкие physical i.MX8MP ACS/grant/recovery. Это не общий Guardian-routed full+resilience с M-02 sealed mTLS bootstrap. ArlanPhone [#135](https://github.com/1day0fmylife/ArlanPhone/pull/135) исправил FIFO CPU spin на плате, а не весь hardware gate. SunkarDAV D-03 исправил SDK transport lease, но versioned nested release/pin в телефоне должен пройти отдельно.

## Очередь конкретных работ

1. **P0: [Guardian #17](https://github.com/1day0fmylife/Guardian/issues/17) X-01/M-04:** один exact-main managed route, реальные DAV auth/read/write/sync, ACS Inform → Admiral NBI, M-02 private mTLS/sealed credential, M-03/A-06 signed assignment/Range на одном WG peer с image/SHA/capture. Device network **никогда** не экспонирует Admiral admin/ACS NBI.
2. **P0: Guardian #17 X-02:** 18 негативных и recovery-сценариев на этом же комплекте — отсутствующие проверки не PASS.
3. **P1: [ArlanPhone #136](https://github.com/1day0fmylife/ArlanPhone/issues/136) A-08:** production signed RAUC A/B, bootloader/slot/anti-rollback, health, power-cut, physical acceptance. Не повторять PR #134.
4. **P1: [SunkarDAV #47](https://github.com/1day0fmylife/SunkarDAV/issues/47) → [ArlanPhone #137](https://github.com/1day0fmylife/ArlanPhone/issues/137):** выпустить исправленный nested DAV SDK, обновить настоящий versioned pin и тесты.
5. **P1: [SunkarCWMP #19](https://github.com/1day0fmylife/SunkarCWMP/issues/19) / [#12](https://github.com/1day0fmylife/SunkarCWMP/issues/12) / [ArlanPhone #68](https://github.com/1day0fmylife/ArlanPhone/issues/68):** exact-selected ACS release E2E, настоящий pilot with independent off-host backup/key escrow, статус socket ACL физического устройства, boot/power/recovery.
6. **P1: [ArlanMeet #22](https://github.com/1day0fmylife/ArlanMeet/issues/22):** clean-host SIP/real phone & media SLO; 8-party 1.2–1.4% audio loss на swap/iowait-хосте не считать квалифицированным PASS при SLO 1%.
7. **После read-only gate:** A-09/C-05/M-05 typed writes; G-09 remote node-agent только после измерений и отдельного решения.

## Issue reconciliation 12.10.2026

- [ArlanPhone #122](https://github.com/1day0fmylife/ArlanPhone/issues/122) закрыт: pinned unpatched v0.2.1 и опубликованный SHA256 проверены; физический и exact-release gate отслеживаются отдельно.
- Датированные актуализации добавлены в [ArlanPhone #68](https://github.com/1day0fmylife/ArlanPhone/issues/68), [Admiral #2](https://github.com/1day0fmylife/Admiral/issues/2), [SunkarCWMP #2](https://github.com/1day0fmylife/SunkarCWMP/issues/2), [#12](https://github.com/1day0fmylife/SunkarCWMP/issues/12), [#19](https://github.com/1day0fmylife/SunkarCWMP/issues/19); прежние тела сохранены как история. Новые follow-ups: Guardian #17, ArlanPhone #136/#137, SunkarDAV #47, ArlanMeet #22.

**Предписание Codex:** сперва сравнить с `main` и PR/Issue; не воспроизводить merged работу, реализовывать только указанный delta. Один ограниченный PR по одному владельцу/репозиторию; отчёт должен содержать точные SHA, versioned артефакты, выполненные команды и невыполненные installed/hardware проверки. Нельзя заявлять pilot, physical или HA по одному компонентному тесту.
