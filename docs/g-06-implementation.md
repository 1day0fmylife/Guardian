# G-06 — operator service access, enrollment QR and diagnostics

## Baseline and remaining delta

Inspected `main` at `cc3d92ccf7b1a6bba3a7e3ebdfbb98f0f04d7099`
(2026-10-10, G-05 merged), `AGENTS.md`, `PLAN.md`, domain models, admin/device
API, RBAC, migrations 001–007 and open PRs (none at inspection).
The supplied ecosystem plan calls G-06 the operator WebUI task. The requested
catalog/API/migration functionality already exists in G-01/G-04/G-05:

| Existing capability | Reused implementation |
| --- | --- |
| Versioned SunkarDAV / Admiral device / SunkarCWMP ACS catalog | domain/service_catalog.go, store/service_catalog.go, migration 006 |
| Individual and tenant/site/group grants, precedence, deny by default | Same domain/store; services start disabled without grants |
| Admin catalog/grants/scopes API and permissions | httpapi/service_api.go, services.read/manage in rbac |
| Non-secret per-device effective policy | GET /api/v1/device/services; credential-bound, no upstream credentials |
| Revision wake/poll and durable revocation | G-04/G-05; migrations 006–007 |
| Hashed, expiring, one-time enrollment and provisioning URI | Existing enrollment API/store |

No duplicate service model, grant API or migration is added. Full tests migrate
fresh databases through 001–007 on SQLite and PostgreSQL. Existing API response
shapes and role permissions remain compatible.

## Operator flow

Open Devices → device details → Service access. Read access requires
`services.read`; `services.manage` reveals individual Allow/Deny/Inherit and
catalog editing. Current access state, policy revision, each service revision,
decision reason and inherited membership are shown. This is desired policy;
it is not proof that gateway rules were applied or an upstream login succeeded.

- Allow establishes an explicit device override independently per service.
- Deny blocks the service even when a broader scope grants it.
- Inherit removes the individual rule. A broader grant can restore access;
  confirmation explains this. Use Deny to guarantee a device override blocks it.
- Disabled services and inactive/suspended/revoked devices cannot acquire
  effective access. Catalog mutations use the existing expected_revision check.
- Catalog forms retain drafts during polling. A newer revision requires explicit
  reload; validation/API errors remain visible and are not treated as success.

The catalog editor uses existing protocol/TLS validation and allowed scopes.
It affects all devices, which its confirmation makes explicit. No credentials,
admin/NBI paths or full upstream URLs are added to policy.

The device timeline requires `audit.read` independently and displays actor,
action and time. New additive endpoint `GET /api/v1/devices/{id}/audit` uses the
existing audit table, filtering before server-side pagination (20 per UI page).
Device events and explicit device-grant history are included; global catalog and
scoped changes are available in the existing global Audit view. An unknown
device yields 404 and unauthorized readers receive 401/403. The global audit
API retains its shape. Equal timestamps now have a stable ID ordering.

## Enrollment and security

The existing issuance response renders as a local SVG QR via `qrcode.react`;
no remote QR service receives the URI/token. Manual token/URI copy remains.
Creation and revocation controls now respect their individual permissions.
The raw output is removed from the React Query mutation cache and retained only
in the issued card's component state. Hide, unmount, local expiry, observed
consumption and successful local revocation clear it. Other-client consumption
is observed by the existing 15-second enrollment poll; server-side single-use
validation remains immediate. Clipboard failures have manual recovery.

Profiles/pools already support creation and selection needed by enrollment.
Their unrelated edit/delete paths are not necessary for this flow and remain
out of scope. Existing EN/light/dark UI is preserved; there is no localization
provider in current main, so a new RU/KK translation framework is not introduced.

## Executed validation (2026-10-10)

- `GUARDIAN_TEST_POSTGRES_URL=<disposable local PostgreSQL 16 URL> go test ./...`:
  PASS; SQLite and PostgreSQL service/migration matrix, including new device
  audit isolation/actor/pagination test.
- `go vet ./...`: PASS.
- `CGO_ENABLED=0 go build -o /tmp/guardian-g06-server ./cmd/guardian`: PASS.
- `go test -race ./...`: PASS (SQLite fixtures; PostgreSQL matrix runs above).
- `bun run test` in web: PASS, 6 tests / 24 assertions. Read-only service and
  enrollment UI, independent permission gates, explicit catalog request allowlist.
- `bun run build` in web: PASS; Vite warns about the main bundle exceeding 500 kB.
- `docker compose config --quiet`: PASS.
- `git diff --check`: PASS.
- Real Chromium via Playwright CLI against isolated local API/SQLite: DAV Allow
  changed policy revision 5→6 while ACS/Admiral remained denied; Inherit revoked
  it, revision 7 returned DAV to denied and timeline showed actor/revoke. Modal
  starts at Cancel; Tab/Enter confirms. Light and Dark access panels inspected.
- QR SVG displayed locally with no enrollment token in browser storage; manual
  enrollment using that URI returned 201, replay returned 409, polling removed
  the QR after consumption. Existing API tests cover expiry, binding and revocation.

Existing service API/store tests cover role boundaries, two-device isolation,
revoked/suspended devices and grants, secret-free policy, forged identity headers,
revision conflicts/idempotency and backward-compatible endpoints. New endpoint
negative tests reject anonymous/device credentials and viewer/operator audit access.
Frontend tests are available via `bun run test`. Adding that command to the existing
CI web job remains a follow-up: the current publishing credential lacks GitHub
workflow scope, so this PR preserves the existing workflow unchanged.

No installed gateway, downstream phone UI, physical camera, real service traffic,
or hardware acceptance is claimed. Physical camera scanning and installed-stack
propagation remain field gates. Browser console 404s were expected absent-telemetry
responses in the fixture and are handled by the existing empty telemetry UI.
