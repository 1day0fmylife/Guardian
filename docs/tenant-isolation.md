# Tenant, site/group and tunnel address isolation (G-08)

The existing service API, grant precedence and permission names remain in use.
A tenant ID is an opaque global identifier. Site IDs and group IDs are also
global identifiers, not display names: use distinct IDs such as `acme:office-1`
and `other:office-1` for sites with the same human-readable name.

First successful `PUT /api/v1/devices/{id}/scopes` binds each site/group ID to
that request's tenant. Ownership is immutable and persists after its last
membership is removed, preventing an old grant from being inherited by another
tenant. Moving a device to another tenant requires replacing its site/groups
with IDs owned by the destination. This is an explicit, audited global-admin
operation. Assign memberships before issuing scoped grants; the existing API
still accepts grants for IDs not yet assigned to devices.

Empty tenant is the existing standalone namespace, never a wildcard. Existing
unscoped devices and same-namespace sites/groups continue to work. A legacy
site/group cannot later be attached to a named tenant; allocate new IDs and
review grants explicitly. Devices may belong to one tenant, one site and up to
64 groups, all owned by that tenant namespace. Group and site IDs are separate
identifier namespaces. No new entity-management UI or parallel grant engine is
introduced.

Cross-owner membership returns `409 scope_tenant_conflict`. The entire request,
including newly registered IDs, policy revision and audit event, rolls back.
Concurrent writers serialize ownership decisions on the existing policy-state
row. Both device policy and the bulk gateway snapshot validate ownership and
fail closed for inconsistent offline edits. A device credential can fetch only
its own policy; tenant, site/group memberships and another device's credentials
never appear in that response.

Admin/operator/auditor/viewer permissions remain platform-wide. Guardian has
no tenant-bound admin principals or delegated tenant administrators. Membership
is a device service-policy boundary, not an admin-account visibility filter.
Only `services.manage` can replace scopes or grants; operator/viewer cannot.
Deploy separate Guardian instances if administrative confidentiality between
independent customers is required. Global admins may intentionally issue device
overrides, with existing audit and precedence rules.

## Tunnel addressing and packet isolation

One reference Guardian database serves one gateway network namespace. All
IPv4 pools must be non-overlapping globally, including across tenant namespaces
and VPN profiles. A serialized pool-create transaction compares masked CIDRs;
exact matches, containment and noncanonical aliases return
`409 address_pool_overlap`. Administrative pool creation and audit commit
together. Existing store callers retain their create method.

The allocator checks active/revoking addresses globally, with a database unique
index as a final guard. Revoking addresses remain reserved until peer removal
and required ACL acknowledgement complete. Released history remains reusable.
Pools are shared infrastructure, not evidence of tenant membership; a tenant
may use a shared pool without gaining any service or lateral access.

Reference gateway `forward` remains default-drop; devices cannot reach other
peers, the control plane or direct upstream networks. Service INPUT sets grant
only known /32 peer bindings. WireGuard cryptokey routing rejects forged source
addresses. Grants authorize shared service endpoints; backend data isolation
still requires each service's own authentication. Guardian does not distribute
backend account credentials or grant access by default.

## Migration 009 and legacy data

Stop writers and take a protected backup before upgrading. Migration 009
backfills owners from existing memberships, enforces one tenant/site per device,
adds global active/revoking lease uniqueness and the pool serialization row.
It preserves service definitions, grants, credentials and policy revisions.
Repeated startup is idempotent.

Ambiguous ownership, overlapping pools or duplicate occupied addresses must
be resolved offline before upgrade; migration failure rolls back its changes
and stops startup. Never rename a shared ID or move a live peer address blindly:
keep the old gateway fenced, identify intended owners, revoke ambiguous grants,
allocate unique destination IDs/non-overlapping pools and re-enroll affected
devices with reviewed grants. Verify a clean restored copy before cutover.
Do not downgrade to a binary that ignores ownership or global pool checks.
