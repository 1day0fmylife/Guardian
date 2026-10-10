# Guardian operator UX contract

Reviewed 2026-10-10 against `PLAN.md`, `internal/rbac/rbac.go`,
`internal/domain/service_catalog.go` and `docs/service-catalog.md`.

Runtime tokens and themes: `web/src/styles.css`; visual context: `DESIGN.md`.
Canonical sibling flows: device actions, network configuration and enrollments.
React Query owns server state; native labeled input/select/checkbox own field interaction;
semantic tables own comparison, `table-scroll` owns horizontal overflow. Buttons and
inline alerts use the existing shared CSS recipes. Dates use browser locale/timezone.
Current UI language is English; there is no RU/KK/EN localization provider.

Service policy and catalog require services.read; changes require services.manage.
Audit requires audit.read independently. Enrollment creation and revocation are separately
gated. Server authorization remains authoritative, including after session permissions change.
Hide unauthorized actions; disable in-flight actions. Do not optimistically claim access.

Allow/Deny creates an individual override. Inherit removes it and may restore scoped
access. All service changes use a modal confirmation naming the consequence. Native
`dialog` provides inert background and Escape; cancel gets initial focus and closing
restores focus. Save waits for acknowledgement and invalidates policy/catalog/audit.
Errors stay inline; drafts remain on failure. Revision conflicts require refreshing the
catalog before resubmitting. Catalog polling never overwrites a dirty draft silently.

The catalog is bounded to three services. Device audit uses server pages of 20;
page position is transient within device details (not a shareable global audit filter).
Loading, empty and error states are explicit, with retry. Audit excludes scoped/global
changes and explains where to find them. Policy revision means desired access, not proof
of applied gateway rules or service health.

Provisioning QR is generated locally from the existing URI. Plaintext lives only in the
issued card's React state, never persistent storage, URLs, telemetry or React Query mutation
cache. Clear on hide, unmount, local expiry, known consumption or revocation. Consumption
on another client is detected by enrollment polling; the server still enforces one use.
Clipboard failure permits manual copy and never displays secrets in feedback.

Keyboard focus must remain visible. Preserve horizontal table comparison on mobile,
light/dark themes and readable labels. Physical camera acceptance is a separate field gate.
Legacy device actions still use browser confirmations; migrating unrelated flows is outside
this change. New service confirmations use the app-owned native dialog variant.
