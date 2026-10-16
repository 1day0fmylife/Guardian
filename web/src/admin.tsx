import React from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { keepPreviousData } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import {
  flexRender,
  getCoreRowModel,
  useReactTable,
  type ColumnDef,
  type PaginationState,
  type SortingState,
} from '@tanstack/react-table'
import axios from 'axios'
import {
  createRole,
  lockUser,
  unlockUser,
  type UserListParams,
  type UserSortKey,
  type UserStatusFilter,
  createUser,
  getMe,
  getSettings,
  listAudit,
  listCommands,
  listPermissions,
  listRoles,
  listUsers,
  resetUserPassword,
  updateRole,
  updateSettings,
  updateUser,
  type AuditEvent,
  type DeviceCommand,
  type Role,
  type User,
} from './api'

function errorMessage(error: unknown) {
  if (axios.isAxiosError(error)) {
    const payload = error.response?.data as { error?: { message?: string } } | undefined
    return payload?.error?.message || error.message
  }
  return error instanceof Error ? error.message : 'Request failed'
}

function hasPermission(permissions: string[] | undefined, permission: string) {
  return Boolean(permissions?.includes(permission))
}

const userPageSizes = [10, 25, 50, 100] as const

export function UsersPage() {
  const queryClient = useQueryClient()
  const roles = useQuery({ queryKey: ['admin-roles'], queryFn: listRoles })
  const me = useQuery({ queryKey: ['me'], queryFn: getMe })
  const [search, setSearch] = React.useState('')
  const [debouncedSearch, setDebouncedSearch] = React.useState('')
  const [status, setStatus] = React.useState<UserStatusFilter>('')
  const [role, setRole] = React.useState('')
  const [sorting, setSorting] = React.useState<SortingState>([{ id: 'username', desc: false }])
  const [pagination, setPagination] = React.useState<PaginationState>({ pageIndex: 0, pageSize: 25 })
  const [editingId, setEditingId] = React.useState<string | null>(null)
  const canCreate = hasPermission(me.data?.permissions, 'users.create')
  const canUpdate = hasPermission(me.data?.permissions, 'users.update')

  React.useEffect(() => {
    const timer = window.setTimeout(() => setDebouncedSearch(search.trim()), 250)
    return () => window.clearTimeout(timer)
  }, [search])
  // Any filter change returns to the first page so the offset stays valid.
  React.useEffect(() => { setPagination((current) => ({ ...current, pageIndex: 0 })) }, [debouncedSearch, status, role])

  const params: UserListParams = {
    limit: pagination.pageSize,
    offset: pagination.pageIndex * pagination.pageSize,
    q: debouncedSearch,
    status,
    role,
    sort: (sorting[0]?.id as UserSortKey | undefined) ?? 'username',
    desc: sorting[0]?.desc ?? false,
  }
  const users = useQuery({ queryKey: ['admin-users', params], queryFn: () => listUsers(params), placeholderData: keepPreviousData })

  const refresh = async () => {
    await queryClient.invalidateQueries({ queryKey: ['admin-users'] })
    await queryClient.invalidateQueries({ queryKey: ['me'] })
  }

  const columns = React.useMemo<ColumnDef<User>[]>(() => [
    { id: 'username', header: 'User', enableSorting: true, cell: ({ row }) => <div className="device-name"><strong>{row.original.display_name || row.original.username}</strong><span>{row.original.username}</span></div> },
    { id: 'roles', header: 'Roles', enableSorting: false, cell: ({ row }) => <div className="chip-row">{row.original.roles.map((value) => <span className="count-chip" key={value}>{value}</span>)}</div> },
    { id: 'status', header: 'Status', enableSorting: false, cell: ({ row }) => <UserStatus user={row.original} /> },
    { id: 'created_at', header: 'Created', enableSorting: true, cell: ({ row }) => formatDate(row.original.created_at) },
    { id: 'updated_at', header: 'Updated', enableSorting: true, cell: ({ row }) => formatDate(row.original.updated_at) },
    { id: 'actions', header: () => <span className="sr-only">Actions</span>, enableSorting: false, cell: ({ row }) => canUpdate ? <button className="secondary-button" type="button" onClick={() => setEditingId(row.original.id)}>Manage</button> : null },
  ], [canUpdate])

  const total = users.data?.total ?? 0
  const table = useReactTable({
    data: users.data?.items ?? [],
    columns,
    getCoreRowModel: getCoreRowModel(),
    manualPagination: true,
    manualSorting: true,
    enableSortingRemoval: false,
    rowCount: total,
    state: { sorting, pagination },
    onSortingChange: setSorting,
    onPaginationChange: setPagination,
    getRowId: (user) => user.id,
  })

  if (roles.isPending || me.isPending) return <LoadingPanel />
  if (roles.isError) return <ErrorPanel error={roles.error} retry={() => roles.refetch()} />
  const editing = users.data?.items.find((user) => user.id === editingId) ?? null
  const firstRow = total === 0 ? 0 : pagination.pageIndex * pagination.pageSize + 1
  const lastRow = Math.min(total, (pagination.pageIndex + 1) * pagination.pageSize)

  return (
    <section className="page-stack">
      <PageHeading title="Users" description="Guardian accounts and their RBAC roles. New accounts and password resets issue a temporary password that must be changed at first sign-in." count={users.data ? `${total} users` : undefined} />
      {canCreate && <UserCreateForm roles={roles.data ?? []} onCreated={refresh} />}
      {editing && <UserEditPanel key={editing.id} user={editing} roles={roles.data ?? []} currentUserId={me.data?.user_id ?? ''} onClose={() => setEditingId(null)} onSaved={refresh} />}
      <article className="table-panel">
        <div className="table-toolbar" role="search">
          <label className="field-label search">Search<input type="search" placeholder="Username or display name" value={search} onChange={(e) => setSearch(e.target.value)} /></label>
          <label className="field-label">Status<select value={status} onChange={(e) => setStatus(e.target.value as UserStatusFilter)}><option value="">All</option><option value="active">Active</option><option value="disabled">Locked</option><option value="password_change">Password change pending</option></select></label>
          <label className="field-label">Role<select value={role} onChange={(e) => setRole(e.target.value)}><option value="">Any role</option>{(roles.data ?? []).map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label>
        </div>
        {users.isError ? <ErrorPanel error={users.error} retry={() => users.refetch()} /> : (
          <div className="table-scroll">
            <table className="data-table admin-table" aria-busy={users.isFetching}>
              <thead>{table.getHeaderGroups().map((group) => <tr key={group.id}>{group.headers.map((header) => {
                const sorted = header.column.getIsSorted()
                return <th key={header.id} aria-sort={sorted === 'asc' ? 'ascending' : sorted === 'desc' ? 'descending' : undefined}>
                  {header.column.getCanSort()
                    ? <button className="sort-button" type="button" onClick={header.column.getToggleSortingHandler()}>{flexRender(header.column.columnDef.header, header.getContext())}<span className="material-symbols-rounded" aria-hidden="true">{sorted === 'asc' ? 'arrow_upward' : sorted === 'desc' ? 'arrow_downward' : 'unfold_more'}</span></button>
                    : flexRender(header.column.columnDef.header, header.getContext())}
                </th>
              })}</tr>)}</thead>
              <tbody>
                {users.isPending && <tr><td className="empty-cell" colSpan={columns.length}>Loading…</td></tr>}
                {table.getRowModel().rows.map((row) => <tr key={row.id}>{row.getVisibleCells().map((cell) => <td key={cell.id} className={cell.column.id === 'actions' ? 'table-actions' : undefined}>{flexRender(cell.column.columnDef.cell, cell.getContext())}</td>)}</tr>)}
                {!users.isPending && table.getRowModel().rows.length === 0 && <tr><td className="empty-cell" colSpan={columns.length}>No users match the current filters.</td></tr>}
              </tbody>
            </table>
          </div>
        )}
        <div className="table-pager">
          <span>{firstRow}–{lastRow} of {total}</span>
          <div className="pager-buttons">
            <label className="field-label">Rows<select value={pagination.pageSize} onChange={(e) => table.setPageSize(Number(e.target.value))}>{userPageSizes.map((size) => <option key={size} value={size}>{size}</option>)}</select></label>
            <button className="secondary-button" type="button" disabled={!table.getCanPreviousPage()} onClick={() => table.previousPage()} aria-label="Previous page"><span className="material-symbols-rounded">chevron_left</span></button>
            <span>Page {pagination.pageIndex + 1} of {Math.max(1, table.getPageCount())}</span>
            <button className="secondary-button" type="button" disabled={!table.getCanNextPage()} onClick={() => table.nextPage()} aria-label="Next page"><span className="material-symbols-rounded">chevron_right</span></button>
          </div>
        </div>
      </article>
    </section>
  )
}

export function UserStatus({ user }: { user: User }) {
  if (user.disabled) return <span className="badge warn"><span className="dot" />Locked</span>
  if (user.must_change_password) return <span className="badge neutral"><span className="dot" />Password change pending</span>
  return <span className="badge ok"><span className="dot" />Active</span>
}

/** Random temporary password; the user must replace it at first sign-in. */
export function generateTemporaryPassword(length = 20) {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_'
  const bytes = new Uint32Array(length)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, (value) => alphabet[value % alphabet.length]).join('')
}

function TemporaryPasswordField({ value, onChange, label }: { value: string; onChange: (value: string) => void; label: string }) {
  return (
    <div className="temp-password">
      <label className="field-label">{label}<input type="text" spellCheck={false} autoComplete="off" value={value} onChange={(e) => onChange(e.target.value)} /></label>
      <button className="secondary-button" type="button" onClick={() => onChange(generateTemporaryPassword())}><span className="material-symbols-rounded">casino</span>Generate</button>
    </div>
  )
}

function UserCreateForm({ roles, onCreated }: { roles: Role[]; onCreated: () => Promise<void> }) {
  const [username, setUsername] = React.useState('')
  const [displayName, setDisplayName] = React.useState('')
  const [password, setPassword] = React.useState('')
  const [selectedRoles, setSelectedRoles] = React.useState<string[]>(['viewer'])
  const [created, setCreated] = React.useState<string | null>(null)
  const mutation = useMutation({
    mutationFn: () => createUser({ username: username.trim(), display_name: displayName.trim(), password, roles: selectedRoles }),
    onSuccess: async (user) => { setCreated(user.username); setUsername(''); setDisplayName(''); setPassword(''); setSelectedRoles(['viewer']); await onCreated() },
  })
  return (
    <article className="panel admin-form-panel">
      <div><h2>Create user</h2><p>Assign one or more roles and a temporary password. Hand the password over out of band; Guardian requires the user to change it at first sign-in.</p></div>
      <div className="form-grid three">
        <label className="field-label">Username<input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off" /></label>
        <label className="field-label">Display name<input value={displayName} onChange={(e) => setDisplayName(e.target.value)} /></label>
        <TemporaryPasswordField label="Temporary password" value={password} onChange={setPassword} />
      </div>
      <RoleChecklist roles={roles} selected={selectedRoles} onChange={setSelectedRoles} />
      {mutation.isError && <div className="alert danger" role="alert">{errorMessage(mutation.error)}</div>}
      {created && !mutation.isError && <div className="alert success" role="status">User {created} created. They must change the temporary password at first sign-in.</div>}
      <div><button className="primary-button" type="button" disabled={mutation.isPending || !username.trim() || password.length < 12 || selectedRoles.length === 0} onClick={() => { setCreated(null); mutation.mutate() }}>{mutation.isPending ? 'Creating…' : 'Create user'}</button></div>
    </article>
  )
}

function UserEditPanel({ user, roles, currentUserId, onClose, onSaved }: { user: User; roles: Role[]; currentUserId: string; onClose: () => void; onSaved: () => Promise<void> }) {
  const [displayName, setDisplayName] = React.useState(user.display_name)
  const [selectedRoles, setSelectedRoles] = React.useState<string[]>(user.roles)
  const [newPassword, setNewPassword] = React.useState('')
  const [notice, setNotice] = React.useState<string | null>(null)
  const save = useMutation({ mutationFn: () => updateUser(user.id, { display_name: displayName.trim(), disabled: user.disabled, roles: selectedRoles }), onSuccess: async () => { setNotice('Roles saved.'); await onSaved() } })
  const lock = useMutation({ mutationFn: () => user.disabled ? unlockUser(user.id) : lockUser(user.id), onSuccess: async (updated) => { setNotice(updated.disabled ? 'Account locked; its sessions were revoked.' : 'Account unlocked.'); await onSaved() } })
  const password = useMutation({ mutationFn: () => resetUserPassword(user.id, newPassword), onSuccess: async () => { setNewPassword(''); setNotice('Temporary password set. The user must change it at next sign-in; existing sessions were revoked.'); await onSaved() } })
  const self = user.id === currentUserId
  const error = save.error || lock.error || password.error
  return (
    <article className="panel admin-editor user-editor">
      <div className="editor-heading"><div><h2>Manage {user.username}</h2><p>Role changes apply on the next request. You can only grant roles whose permissions you hold.</p></div><button className="icon-button" type="button" aria-label="Close" onClick={onClose}><span className="material-symbols-rounded">close</span></button></div>
      <div><UserStatus user={user} /></div>
      <label className="field-label">Display name<input value={displayName} onChange={(e) => setDisplayName(e.target.value)} /></label>
      <RoleChecklist roles={roles} selected={selectedRoles} onChange={setSelectedRoles} />
      {error && <div className="alert danger" role="alert">{errorMessage(error)}</div>}
      {notice && !error && <div className="alert success" role="status">{notice}</div>}
      <div className="editor-actions split">
        <button className="primary-button" type="button" disabled={save.isPending || selectedRoles.length === 0} onClick={() => save.mutate()}>Save roles</button>
        <button className="secondary-button" type="button" disabled={lock.isPending || (self && !user.disabled)} title={self ? 'You cannot lock your own account' : undefined} onClick={() => lock.mutate()}>
          <span className="material-symbols-rounded">{user.disabled ? 'lock_open' : 'lock'}</span>{user.disabled ? 'Unlock account' : 'Lock account'}
        </button>
      </div>
      {!self && <div className="password-reset">
        <TemporaryPasswordField label="New temporary password" value={newPassword} onChange={setNewPassword} />
        <button className="secondary-button" type="button" disabled={password.isPending || newPassword.length < 12} onClick={() => password.mutate()}>Reset password</button>
      </div>}
      {self && <p className="form-note">Change your own password from the account menu.</p>}
    </article>
  )
}

function RoleChecklist({ roles, selected, onChange }: { roles: Role[]; selected: string[]; onChange: (roles: string[]) => void }) {
  const toggle = (role: string) => onChange(selected.includes(role) ? selected.filter((value) => value !== role) : [...selected, role])
  return <div className="permission-grid compact">{roles.map((role) => <label className="check-card" key={role.id}><input type="checkbox" checked={selected.includes(role.id)} onChange={() => toggle(role.id)} /><span><strong>{role.name}</strong><small>{role.description}</small></span></label>)}</div>
}

export function RolesPage() {
  const queryClient = useQueryClient()
  const roles = useQuery({ queryKey: ['admin-roles'], queryFn: listRoles })
  const permissions = useQuery({ queryKey: ['admin-permissions'], queryFn: listPermissions })
  const me = useQuery({ queryKey: ['me'], queryFn: getMe })
  const [editing, setEditing] = React.useState<Role | null>(null)
  const canCreate = hasPermission(me.data?.permissions, 'roles.create')
  const canUpdate = hasPermission(me.data?.permissions, 'roles.update')
  if (roles.isPending || permissions.isPending || me.isPending) return <LoadingPanel />
  if (roles.isError) return <ErrorPanel error={roles.error} retry={() => roles.refetch()} />
  if (permissions.isError) return <ErrorPanel error={permissions.error} retry={() => permissions.refetch()} />
  const refresh = async () => { await queryClient.invalidateQueries({ queryKey: ['admin-roles'] }); await queryClient.invalidateQueries({ queryKey: ['me'] }) }
  return (
    <section className="page-stack">
      <PageHeading title="Roles" description="Permission bundles used by Guardian administrators and operators." />
      {canCreate && <RoleEditor permissions={permissions.data ?? []} onSaved={refresh} />}
      <div className="role-list">
        {(roles.data ?? []).map((role) => <article className="panel role-card" key={role.id}><div className="role-heading"><div><h2>{role.name}</h2><p>{role.description}</p></div><span className="count-chip">{role.system ? 'System' : `${role.permissions.length} permissions`}</span></div><div className="permission-summary">{role.permissions.map((permission) => <code key={permission}>{permission}</code>)}</div>{canUpdate && !role.system && <div><button className="secondary-button" type="button" onClick={() => setEditing(role)}>Edit custom role</button></div>}</article>)}
      </div>
      {editing && <RoleEditor role={editing} permissions={permissions.data ?? []} onSaved={async () => { setEditing(null); await refresh() }} onCancel={() => setEditing(null)} />}
    </section>
  )
}

function RoleEditor({ role, permissions, onSaved, onCancel }: { role?: Role; permissions: string[]; onSaved: () => Promise<void>; onCancel?: () => void }) {
  const [name, setName] = React.useState(role?.name ?? '')
  const [description, setDescription] = React.useState(role?.description ?? '')
  const [selected, setSelected] = React.useState<string[]>(role?.permissions ?? [])
  const mutation = useMutation({
    mutationFn: () => role ? updateRole(role.id, { description: description.trim(), permissions: selected }) : createRole({ name: name.trim(), description: description.trim(), permissions: selected }),
    onSuccess: onSaved,
  })
  const groups = React.useMemo(() => groupPermissions(permissions), [permissions])
  const toggle = (permission: string) => setSelected((current) => current.includes(permission) ? current.filter((value) => value !== permission) : [...current, permission])
  return (
    <article className="panel admin-form-panel">
      <div className="editor-heading"><div><h2>{role ? `Edit ${role.name}` : 'Create custom role'}</h2><p>System roles are seeded and immutable; custom roles can be tuned here.</p></div>{onCancel && <button className="icon-button" type="button" onClick={onCancel}><span className="material-symbols-rounded">close</span></button>}</div>
      <div className="form-grid two"><label className="field-label">Role name<input disabled={Boolean(role)} value={name} onChange={(e) => setName(e.target.value)} /></label><label className="field-label">Description<input value={description} onChange={(e) => setDescription(e.target.value)} /></label></div>
      <div className="permission-sections">{Object.entries(groups).map(([group, values]) => <div className="permission-section" key={group}><strong>{group}</strong><div className="permission-grid">{values.map((permission) => <label className="check-card" key={permission}><input type="checkbox" checked={selected.includes(permission)} onChange={() => toggle(permission)} /><span><code>{permission}</code></span></label>)}</div></div>)}</div>
      {mutation.isError && <div className="alert danger">{errorMessage(mutation.error)}</div>}
      <div><button className="primary-button" type="button" disabled={mutation.isPending || (!role && !name.trim()) || selected.length === 0} onClick={() => mutation.mutate()}>{role ? 'Save role' : 'Create role'}</button></div>
    </article>
  )
}

function groupPermissions(permissions: string[]) {
  return permissions.reduce<Record<string, string[]>>((groups, permission) => { const group = permission.split('.')[0] || 'other'; (groups[group] ||= []).push(permission); return groups }, {})
}

export function AuditPage() {
  const query = useQuery({ queryKey: ['audit'], queryFn: () => listAudit(100, 0), refetchInterval: 15_000 })
  if (query.isPending) return <LoadingPanel />
  if (query.isError) return <ErrorPanel error={query.error} retry={() => query.refetch()} />
  return <section className="page-stack"><PageHeading title="Audit" description="Immutable administrative and device-management activity recorded by Guardian." count={`${query.data.total} events`} /><AuditTable items={query.data.items} /></section>
}

function AuditTable({ items }: { items: AuditEvent[] }) {
  return <article className="table-panel"><div className="table-scroll"><table className="data-table admin-table"><thead><tr><th>Time</th><th>Action</th><th>Resource</th><th>Actor</th><th>Source</th><th>Details</th></tr></thead><tbody>{items.map((event) => <tr key={event.id}><td>{formatDate(event.created_at)}</td><td><code>{event.action}</code></td><td>{event.resource_type}<div className="mono subtle">{event.resource_id || '—'}</div></td><td className="mono">{event.actor_user_id || 'system'}</td><td className="mono">{event.source_ip || '—'}</td><td><details><summary>View</summary><pre className="json-details">{prettyJSON(event.details)}</pre></details></td></tr>)}</tbody></table></div></article>
}

export function CommandsPage() {
  const query = useQuery({ queryKey: ['commands-global'], queryFn: () => listCommands(100, 0), refetchInterval: 5_000 })
  if (query.isPending) return <LoadingPanel />
  if (query.isError) return <ErrorPanel error={query.error} retry={() => query.refetch()} />
  return <section className="page-stack"><PageHeading title="Commands" description="Global durable command history across managed devices." count={`${query.data.total} commands`} /><CommandTable items={query.data.items} /></section>
}

function CommandTable({ items }: { items: DeviceCommand[] }) {
  return <article className="table-panel"><div className="table-scroll"><table className="data-table admin-table"><thead><tr><th>Created</th><th>Device</th><th>Command</th><th>Status</th><th>Finished</th><th>Result</th></tr></thead><tbody>{items.map((command) => <tr key={command.id}><td>{formatDate(command.created_at)}</td><td><div className="device-name"><Link to="/devices/$deviceId" params={{ deviceId: command.device_id }}>{command.device_name || command.device_id}</Link><span>{command.device_uuid || command.device_id}</span></div></td><td><code>{command.type}</code></td><td><CommandBadge status={command.status} /></td><td>{command.finished_at ? formatDate(command.finished_at) : '—'}</td><td>{command.error_message ? <span className="danger-text">{command.error_message}</span> : command.result ? <code>{compactJSON(command.result)}</code> : '—'}</td></tr>)}</tbody></table></div></article>
}

function CommandBadge({ status }: { status: string }) {
  const tone = status === 'succeeded' ? 'ok' : status === 'failed' || status === 'expired' ? 'danger' : status === 'running' ? 'warn' : 'neutral'
  return <span className={`badge ${tone}`}><span className="dot" />{status}</span>
}

export function SettingsPage() {
  const queryClient = useQueryClient()
  const settings = useQuery({ queryKey: ['settings'], queryFn: getSettings })
  const me = useQuery({ queryKey: ['me'], queryFn: getMe })
  const [draft, setDraft] = React.useState<Record<string, string> | null>(null)
  React.useEffect(() => { if (settings.data && draft == null) setDraft({ ...settings.data.values }) }, [settings.data, draft])
  const mutation = useMutation({ mutationFn: () => updateSettings(draft ?? {}), onSuccess: async (value) => { setDraft({ ...value.values }); await queryClient.invalidateQueries({ queryKey: ['settings'] }) } })
  if (settings.isPending || me.isPending || !draft) return <LoadingPanel />
  if (settings.isError) return <ErrorPanel error={settings.error} retry={() => settings.refetch()} />
  const canUpdate = hasPermission(me.data?.permissions, 'settings.update')
  return (
    <section className="page-stack">
      <PageHeading title="Settings" description="Non-secret Guardian control-plane behavior. Deployment secrets remain environment-managed." />
      <article className="panel admin-form-panel">
        <div className="settings-notice"><span className="material-symbols-rounded">security</span><div><strong>Deployment boundary</strong><p>Database URLs, Redis credentials, TLS/private keys and WireGuard private material are intentionally not editable here.</p></div></div>
        <div className="form-grid two">
          <label className="field-label">Site name<input disabled={!canUpdate} value={draft.site_name ?? ''} onChange={(e) => setDraft({ ...draft, site_name: e.target.value })} /></label>
          <label className="field-label">Public URL<input disabled value={settings.data.public_url} /></label>
          <label className="field-label">Default command TTL (seconds)<input disabled={!canUpdate} type="number" min="5" max="86400" value={draft.command_default_ttl_seconds ?? '300'} onChange={(e) => setDraft({ ...draft, command_default_ttl_seconds: e.target.value })} /></label>
          <label className="field-label">Telemetry stale threshold (seconds)<input disabled={!canUpdate} type="number" min="5" max="86400" value={draft.telemetry_stale_seconds ?? '120'} onChange={(e) => setDraft({ ...draft, telemetry_stale_seconds: e.target.value })} /></label>
        </div>
        {mutation.isError && <div className="alert danger">{errorMessage(mutation.error)}</div>}
        {canUpdate && <div><button className="primary-button" type="button" disabled={mutation.isPending} onClick={() => mutation.mutate()}>{mutation.isPending ? 'Saving…' : 'Save settings'}</button></div>}
      </article>
    </section>
  )
}

function PageHeading({ title, description, count }: { title: string; description: string; count?: string }) {
  return <div className="section-heading"><div><h2>{title}</h2><p>{description}</p></div>{count && <span className="count-chip">{count}</span>}</div>
}

function prettyJSON(value?: string) {
  if (!value) return '{}'
  try { return JSON.stringify(JSON.parse(value), null, 2) } catch { return value }
}
function compactJSON(value: unknown) { try { return JSON.stringify(value) } catch { return String(value) } }
function formatDate(value: string) { if (!value) return '—'; const date = new Date(value); return Number.isNaN(date.getTime()) ? value : new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(date) }
function LoadingPanel() { return <article className="panel loading-panel">Loading…</article> }
function ErrorPanel({ error, retry }: { error: unknown; retry: () => void }) { return <article className="alert danger"><span>{errorMessage(error)}</span><button className="secondary-button" type="button" onClick={retry}>Retry</button></article> }
