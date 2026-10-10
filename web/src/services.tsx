import React from 'react'
import axios from 'axios'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { getAdminDevicePolicy, listServices, listDeviceGrants, setDeviceGrant, revokeServiceGrant, updateService, listDeviceAudit, type ServiceDefinition } from './api'
import './services.css'

function message(error: unknown) {
  return axios.isAxiosError(error) ? error.response?.data?.error?.message || 'Request failed. Refresh and retry.' : 'Request failed. Refresh and retry.'
}
function Confirm({ text, cancel, apply }: { text: string; cancel: () => void; apply: () => void }) {
  const ref = React.useRef<HTMLDialogElement>(null)
  React.useEffect(() => { const previous = document.activeElement as HTMLElement | null; ref.current?.showModal(); return () => previous?.focus() }, [])
  return <dialog ref={ref} className="service-dialog" aria-labelledby="service-confirm-title" onCancel={cancel}>
    <h2 id="service-confirm-title">Change service access</h2><p>{text}</p>
    <div className="device-actions"><button autoFocus className="secondary-button" onClick={cancel}>Cancel</button><button className="primary-button" onClick={apply}>Apply change</button></div>
  </dialog>
}
export function DeviceServices({ deviceId, permissions }: { deviceId: string; permissions: Set<string> }) {
  const client = useQueryClient()
  const readable = permissions.has('services.read'), manageable = permissions.has('services.manage')
  const policy = useQuery({ queryKey: ['service-policy', deviceId], queryFn: () => getAdminDevicePolicy(deviceId), enabled: readable, refetchInterval: 5000 })
  const catalog = useQuery({ queryKey: ['services'], queryFn: listServices, enabled: readable, refetchInterval: 15000 })
  const [pending, setPending] = React.useState<{ text: string; run: () => Promise<unknown> } | null>(null)
  const [feedback, setFeedback] = React.useState('')
  const mutation = useMutation({ mutationFn: (run: () => Promise<unknown>) => run(), onSuccess: async () => {
    setFeedback('Change saved. Policy refreshed; gateway application may still be pending.')
    await Promise.all([client.invalidateQueries({ queryKey: ['service-policy'] }), client.invalidateQueries({ queryKey: ['services'] }), client.invalidateQueries({ queryKey: ['device-audit', deviceId] })])
  } })
  if (!readable) return permissions.has('audit.read') ? <DeviceAudit deviceId={deviceId} /> : null
  return <>
    <article className="panel page-stack services-panel" aria-label="Service access">
      <div><div className="eyebrow">Managed network</div><h2>Service access</h2><p>Network permission does not replace DAV or ACS credentials. No access is granted by default.</p></div>
      {policy.isPending && <p role="status">Loading policy…</p>}
      {policy.isError && <div role="alert" className="alert danger">{message(policy.error)} <button onClick={() => void policy.refetch()}>Retry</button></div>}
      {catalog.isError && <div role="alert" className="alert danger">{message(catalog.error)} <button onClick={() => void catalog.refetch()}>Retry catalog</button></div>}
      {policy.data && <>
        <p className="mono">Access state: {policy.data.access_state} · Policy revision: {policy.data.revision}</p>
        <p>Tenant: {policy.data.scopes.tenant_id || '—'} · Site: {policy.data.scopes.site_id || '—'} · Groups: {policy.data.scopes.group_ids.join(', ') || '—'}</p>
        <div className="table-scroll"><table className="data-table"><thead><tr><th>Service</th><th>Effective access</th><th>Individual permission</th></tr></thead><tbody>
          {policy.data.services.map(row => <tr key={row.service_id}>
            <td><strong>{row.display_name}</strong><div className="mono">{row.service_id} · revision {row.service_revision}</div></td>
            <td><span className={`badge ${row.allowed ? 'ok' : 'danger'}`}>{row.allowed ? 'Allowed' : 'Blocked'}</span><p>{row.reason.replaceAll('_', ' ')}</p></td>
            <td>{manageable ? <div className="device-actions">
              {(['allow', 'deny'] as const).map(effect => <button key={effect} className="secondary-button" disabled={mutation.isPending || (effect === 'allow' && policy.data.access_state !== 'active') || !catalog.data?.find(s => s.id === row.service_id)?.allowed_scopes.includes('device')} onClick={() => setPending({ text: `${effect === 'allow' ? 'Allow' : 'Block'} ${row.display_name} for this device, overriding inherited permissions? Access also requires an enabled service and active device.`, run: () => setDeviceGrant(row.service_id, deviceId, effect) })}>{effect === 'allow' ? 'Allow' : 'Deny'}</button>)}
              <button className="secondary-button" disabled={mutation.isPending} onClick={() => setPending({ text: `Remove the individual rule for ${row.display_name}? Tenant, site or group permissions may restore access. To block access use Deny.`, run: async () => { const grants = await listDeviceGrants(row.service_id, deviceId); for (const grant of grants) await revokeServiceGrant(row.service_id, grant.id) } })}>Inherit</button>
            </div> : <span>Read only</span>}</td>
          </tr>)}
        </tbody></table></div>
      </>}
      <div role="status">{mutation.isPending ? 'Saving…' : feedback}</div>
      {mutation.isError && <div role="alert" className="alert danger">{message(mutation.error)}</div>}
      <details><summary>Service catalog</summary><p>Catalog changes affect every device. Saves require the current revision.</p>
        {catalog.data?.map(service => <CatalogEntry key={service.id} service={service} manageable={manageable} busy={mutation.isPending} save={draft => setPending({ text: `Update ${draft.display_name} catalog revision ${draft.revision}? This affects every device using this service.`, run: () => updateService(draft) })} />)}
      </details>
    </article>
    {permissions.has('audit.read') && <DeviceAudit deviceId={deviceId} />}
    {pending && <Confirm text={pending.text} cancel={() => setPending(null)} apply={() => { mutation.mutate(pending.run); setPending(null) }} />}
  </>
}
function CatalogEntry({ service, manageable, busy, save }: { service: ServiceDefinition; manageable: boolean; busy: boolean; save: (s: ServiceDefinition) => void }) {
  const [draft, setDraft] = React.useState(service)
  return <form className="service-catalog form-grid" onSubmit={e => { e.preventDefault(); save(draft) }}>
    <h3>{service.display_name} · revision {service.revision}</h3>
    {draft.revision !== service.revision && <p role="status">A newer catalog revision is available. Reload it before saving.</p>}
    <button className="secondary-button" type="button" disabled={busy} onClick={() => setDraft(service)}>Reload current revision</button><fieldset disabled={!manageable || busy} className="form-grid">
      <label className="field-label">Display name<input required maxLength={80} value={draft.display_name} onChange={e => setDraft({ ...draft, display_name: e.target.value })} /></label>
      <label className="field-label">Internal DNS name<input required value={draft.internal_dns_name} onChange={e => setDraft({ ...draft, internal_dns_name: e.target.value })} /></label>
      <label className="field-label">Protocol<select value={draft.protocol} onChange={e => setDraft({ ...draft, protocol: e.target.value, tls_policy: e.target.value === 'http' ? 'disabled' : 'required' })}><option>https</option><option>http</option><option>tcp</option></select></label>
      <label className="field-label">Port<input required type="number" min={1} max={65535} value={draft.port} onChange={e => setDraft({ ...draft, port: Number(e.target.value) })} /></label>
      <label className="field-label">TLS policy<select value={draft.tls_policy} onChange={e => setDraft({ ...draft, tls_policy: e.target.value })}><option>required</option><option>disabled</option></select></label>
      <div>Allowed scopes{['tenant', 'site', 'group', 'device'].map(scope => <label className="service-check" key={scope}><input type="checkbox" checked={draft.allowed_scopes.includes(scope)} onChange={e => setDraft({ ...draft, allowed_scopes: e.target.checked ? [...draft.allowed_scopes, scope] : draft.allowed_scopes.filter(s => s !== scope) })} />{scope}</label>)}</div>
      <label className="service-check"><input type="checkbox" checked={draft.enabled} onChange={e => setDraft({ ...draft, enabled: e.target.checked })} />Enabled</label>
      {manageable && <button className="primary-button" type="submit" disabled={draft.revision !== service.revision}>Save catalog revision</button>}
    </fieldset>
  </form>
}
function DeviceAudit({ deviceId }: { deviceId: string }) {
  const [offset, setOffset] = React.useState(0)
  const query = useQuery({ queryKey: ['device-audit', deviceId, offset], queryFn: () => listDeviceAudit(deviceId, offset), refetchInterval: 10000 })
  return <article className="panel page-stack"><h2>Device audit timeline</h2><p>Device actions and individual grant changes. Scoped grants and catalog edits appear in the global Audit page.</p>
    {query.isPending && <p role="status">Loading audit…</p>}
    {query.isError && <div role="alert" className="alert danger">{message(query.error)} <button onClick={() => void query.refetch()}>Retry</button></div>}
    {query.data && <><ol>{query.data.items.map(event => <li key={event.id}><time>{new Date(event.created_at).toLocaleString()}</time> · {event.action} · Actor: <span className="mono">{event.actor_user_id || 'Device'}</span></li>)}</ol>{!query.data.items.length && <p>No events on this page.</p>}<div className="device-actions"><button className="secondary-button" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 20))}>Previous</button><span>{query.data.total} events</span><button className="secondary-button" disabled={offset + 20 >= query.data.total} onClick={() => setOffset(offset + 20)}>Next</button></div></>}
  </article>
}
