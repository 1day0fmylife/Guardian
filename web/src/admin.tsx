import React from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import axios from 'axios'
import {
  createRole,
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

export function UsersPage() {
  const queryClient = useQueryClient()
  const users = useQuery({ queryKey: ['admin-users'], queryFn: listUsers })
  const roles = useQuery({ queryKey: ['admin-roles'], queryFn: listRoles })
  const me = useQuery({ queryKey: ['me'], queryFn: getMe })
  const [editing, setEditing] = React.useState<User | null>(null)
  const canCreate = hasPermission(me.data?.permissions, 'users.create')
  const canUpdate = hasPermission(me.data?.permissions, 'users.update')

  const refresh = async () => {
    await queryClient.invalidateQueries({ queryKey: ['admin-users'] })
    await queryClient.invalidateQueries({ queryKey: ['me'] })
  }

  if (users.isPending || roles.isPending || me.isPending) return <LoadingPanel />
  if (users.isError) return <ErrorPanel error={users.error} retry={() => users.refetch()} />
  if (roles.isError) return <ErrorPanel error={roles.error} retry={() => roles.refetch()} />

  return (
    <section className="page-stack">
      <PageHeading title="Users" description="Administrator accounts and assigned RBAC roles." />
      {canCreate && <UserCreateForm roles={roles.data ?? []} onCreated={refresh} />}
      <article className="table-panel">
        <div className="table-scroll">
          <table className="data-table admin-table">
            <thead><tr><th>User</th><th>Roles</th><th>Status</th><th>Updated</th><th /></tr></thead>
            <tbody>
              {(users.data ?? []).map((user) => (
                <tr key={user.id}>
                  <td><div className="device-name"><strong>{user.display_name || user.username}</strong><span>{user.username}</span></div></td>
                  <td><div className="chip-row">{user.roles.map((role) => <span className="count-chip" key={role}>{role}</span>)}</div></td>
                  <td><span className={`badge ${user.disabled ? 'warn' : 'ok'}`}><span className="dot" />{user.disabled ? 'Disabled' : 'Active'}</span></td>
                  <td>{formatDate(user.updated_at)}</td>
                  <td className="table-actions">{canUpdate && <button className="secondary-button" type="button" onClick={() => setEditing(user)}>Edit</button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </article>
      {editing && <UserEditPanel user={editing} roles={roles.data ?? []} currentUserId={me.data?.user_id ?? ''} onClose={() => setEditing(null)} onSaved={async () => { setEditing(null); await refresh() }} />}
    </section>
  )
}

function UserCreateForm({ roles, onCreated }: { roles: Role[]; onCreated: () => Promise<void> }) {
  const [username, setUsername] = React.useState('')
  const [displayName, setDisplayName] = React.useState('')
  const [password, setPassword] = React.useState('')
  const [selectedRoles, setSelectedRoles] = React.useState<string[]>(['viewer'])
  const mutation = useMutation({
    mutationFn: () => createUser({ username: username.trim(), display_name: displayName.trim(), password, roles: selectedRoles }),
    onSuccess: async () => { setUsername(''); setDisplayName(''); setPassword(''); setSelectedRoles(['viewer']); await onCreated() },
  })
  return (
    <article className="panel admin-form-panel">
      <div><h2>Create user</h2><p>Create a Guardian administrator/operator account and assign one or more roles.</p></div>
      <div className="form-grid three">
        <label className="field-label">Username<input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off" /></label>
        <label className="field-label">Display name<input value={displayName} onChange={(e) => setDisplayName(e.target.value)} /></label>
        <label className="field-label">Initial password<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" /></label>
      </div>
      <RoleChecklist roles={roles} selected={selectedRoles} onChange={setSelectedRoles} />
      {mutation.isError && <div className="alert danger">{errorMessage(mutation.error)}</div>}
      <div><button className="primary-button" type="button" disabled={mutation.isPending || !username.trim() || !password || selectedRoles.length === 0} onClick={() => mutation.mutate()}>{mutation.isPending ? 'Creating…' : 'Create user'}</button></div>
    </article>
  )
}

function UserEditPanel({ user, roles, currentUserId, onClose, onSaved }: { user: User; roles: Role[]; currentUserId: string; onClose: () => void; onSaved: () => Promise<void> }) {
  const [displayName, setDisplayName] = React.useState(user.display_name)
  const [disabled, setDisabled] = React.useState(user.disabled)
  const [selectedRoles, setSelectedRoles] = React.useState<string[]>(user.roles)
  const [newPassword, setNewPassword] = React.useState('')
  const save = useMutation({ mutationFn: () => updateUser(user.id, { display_name: displayName.trim(), disabled, roles: selectedRoles }), onSuccess: onSaved })
  const password = useMutation({ mutationFn: () => resetUserPassword(user.id, newPassword), onSuccess: async () => { setNewPassword(''); await onSaved() } })
  const self = user.id === currentUserId
  return (
    <article className="panel admin-editor">
      <div className="editor-heading"><div><h2>Edit {user.username}</h2><p>Changing roles applies on the next authenticated request. Disabling an account revokes its sessions.</p></div><button className="icon-button" type="button" aria-label="Close" onClick={onClose}><span className="material-symbols-rounded">close</span></button></div>
      <label className="field-label">Display name<input value={displayName} onChange={(e) => setDisplayName(e.target.value)} /></label>
      <RoleChecklist roles={roles} selected={selectedRoles} onChange={setSelectedRoles} />
      <label className="toggle-row"><input type="checkbox" checked={disabled} disabled={self} onChange={(e) => setDisabled(e.target.checked)} /><span>Disable account{self ? ' (cannot disable current account)' : ''}</span></label>
      {(save.isError || password.isError) && <div className="alert danger">{errorMessage(save.error || password.error)}</div>}
      <div className="editor-actions"><button className="primary-button" type="button" disabled={save.isPending || selectedRoles.length === 0} onClick={() => save.mutate()}>Save changes</button></div>
      <div className="password-reset"><label className="field-label">New password<input type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} autoComplete="new-password" /></label><button className="secondary-button" type="button" disabled={password.isPending || !newPassword} onClick={() => password.mutate()}>Reset password</button></div>
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
