import React from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import axios from 'axios'
import {
  createAddressPool,
  createVPNProfile,
  getMe,
  listAddressPools,
  listVPNProfiles,
  type AddressPoolCreate,
  type VPNProfileCreate,
} from './api'

function errorMessage(error: unknown) {
  if (axios.isAxiosError(error)) {
    const payload = error.response?.data as { error?: { message?: string } } | undefined
    return payload?.error?.message || error.message
  }
  return error instanceof Error ? error.message : 'Request failed'
}

function splitList(value: string) {
  return value.split(/[\n,]/).map((item) => item.trim()).filter(Boolean)
}

export function AddressPoolsPage() {
  const queryClient = useQueryClient()
  const principal = useQuery({ queryKey: ['me'], queryFn: getMe, staleTime: 30_000 })
  const pools = useQuery({ queryKey: ['address-pools'], queryFn: listAddressPools })
  const [name, setName] = React.useState('')
  const [cidr, setCIDR] = React.useState('10.88.0.0/24')
  const [gateway, setGateway] = React.useState('10.88.0.1')
  const [dns, setDNS] = React.useState('')

  const create = useMutation({
    mutationFn: (input: AddressPoolCreate) => createAddressPool(input),
    onSuccess: async () => {
      setName('')
      await queryClient.invalidateQueries({ queryKey: ['address-pools'] })
    },
  })
  const canCreate = Boolean(principal.data?.permissions.includes('pools.create'))
  const valid = name.trim() !== '' && cidr.trim() !== ''

  return (
    <section className="page-stack">
      <div className="section-heading"><div><h2>Address pools</h2><p>IPv4 address ranges allocated to managed WireGuard peers.</p></div>{pools.data && <span className="count-chip">{pools.data.length} pools</span>}</div>
      {canCreate && (
        <form className="panel config-form" onSubmit={(event) => {
          event.preventDefault()
          if (!valid) return
          create.mutate({ name: name.trim(), cidr: cidr.trim(), gateway: gateway.trim(), dns_servers: splitList(dns) })
        }}>
          <div className="config-form-heading"><div><h2>Create address pool</h2><p>Guardian enforces unique leases from the selected CIDR.</p></div></div>
          <div className="config-form-grid">
            <label className="field-label">Name<input value={name} onChange={(event) => setName(event.target.value)} placeholder="Office phones" /></label>
            <label className="field-label">CIDR<input className="mono" value={cidr} onChange={(event) => setCIDR(event.target.value)} placeholder="10.88.0.0/24" /></label>
            <label className="field-label">Gateway / reserved server IP<input className="mono" value={gateway} onChange={(event) => setGateway(event.target.value)} placeholder="10.88.0.1" /></label>
            <label className="field-label">DNS servers<input className="mono" value={dns} onChange={(event) => setDNS(event.target.value)} placeholder="10.0.0.53, 10.0.0.54" /></label>
          </div>
          {create.isError && <div className="alert danger compact-alert">{errorMessage(create.error)}</div>}
          <div className="form-actions"><button className="primary-button" disabled={!valid || create.isPending} type="submit">{create.isPending ? 'Creating…' : 'Create pool'}</button></div>
        </form>
      )}
      {pools.isPending && <article className="panel loading-panel">Loading address pools…</article>}
      {pools.isError && <article className="alert danger">{errorMessage(pools.error)}</article>}
      {pools.data && (
        <article className="table-panel"><div className="table-scroll"><table className="data-table config-table"><thead><tr><th>Name</th><th>CIDR</th><th>Gateway</th><th>DNS</th><th>Updated</th></tr></thead><tbody>
          {pools.data.map((pool) => <tr key={pool.id}><td><strong className="table-primary">{pool.name}</strong></td><td className="mono">{pool.cidr}</td><td className="mono">{pool.gateway || '—'}</td><td className="mono">{pool.dns_servers?.join(', ') || '—'}</td><td>{formatDate(pool.updated_at)}</td></tr>)}
          {pools.data.length === 0 && <tr><td className="empty-cell" colSpan={5}>Create an address pool before creating a VPN profile.</td></tr>}
        </tbody></table></div></article>
      )}
    </section>
  )
}

export function VPNProfilesPage() {
  const queryClient = useQueryClient()
  const principal = useQuery({ queryKey: ['me'], queryFn: getMe, staleTime: 30_000 })
  const profiles = useQuery({ queryKey: ['vpn-profiles'], queryFn: listVPNProfiles })
  const pools = useQuery({ queryKey: ['address-pools'], queryFn: listAddressPools })
  const [name, setName] = React.useState('')
  const [serverPublicKey, setServerPublicKey] = React.useState('')
  const [endpoint, setEndpoint] = React.useState('')
  const [allowedIPs, setAllowedIPs] = React.useState('0.0.0.0/0')
  const [dns, setDNS] = React.useState('')
  const [keepalive, setKeepalive] = React.useState(25)
  const [poolID, setPoolID] = React.useState('')

  React.useEffect(() => {
    if (!poolID && pools.data?.length) setPoolID(pools.data[0].id)
  }, [poolID, pools.data])

  const create = useMutation({
    mutationFn: (input: VPNProfileCreate) => createVPNProfile(input),
    onSuccess: async () => {
      setName('')
      await queryClient.invalidateQueries({ queryKey: ['vpn-profiles'] })
    },
  })
  const canCreate = Boolean(principal.data?.permissions.includes('profiles.create'))
  const valid = name.trim() !== '' && serverPublicKey.trim() !== '' && endpoint.trim() !== '' && splitList(allowedIPs).length > 0 && poolID !== '' && keepalive >= 0
  const poolNames = new Map((pools.data ?? []).map((pool) => [pool.id, pool.name]))

  return (
    <section className="page-stack">
      <div className="section-heading"><div><h2>VPN profiles</h2><p>Reusable WireGuard server parameters assigned during device enrollment.</p></div>{profiles.data && <span className="count-chip">{profiles.data.length} profiles</span>}</div>
      {canCreate && (
        <form className="panel config-form" onSubmit={(event) => {
          event.preventDefault()
          if (!valid) return
          create.mutate({
            name: name.trim(),
            server_public_key: serverPublicKey.trim(),
            endpoint: endpoint.trim(),
            allowed_ips: splitList(allowedIPs),
            dns_servers: splitList(dns),
            persistent_keepalive: keepalive,
            address_pool_id: poolID,
          })
        }}>
          <div className="config-form-heading"><div><h2>Create VPN profile</h2><p>Only the WireGuard server public key is stored here. Device private keys remain on ArlanPhone.</p></div></div>
          <div className="config-form-grid profile-grid">
            <label className="field-label">Name<input value={name} onChange={(event) => setName(event.target.value)} placeholder="Corporate WireGuard" /></label>
            <label className="field-label">Address pool<select value={poolID} onChange={(event) => setPoolID(event.target.value)}><option value="">Select pool…</option>{pools.data?.map((pool) => <option key={pool.id} value={pool.id}>{pool.name} · {pool.cidr}</option>)}</select></label>
            <label className="field-label field-span-2">Server public key<input className="mono" value={serverPublicKey} onChange={(event) => setServerPublicKey(event.target.value)} placeholder="WireGuard server public key" /></label>
            <label className="field-label">Endpoint<input className="mono" value={endpoint} onChange={(event) => setEndpoint(event.target.value)} placeholder="vpn.example.com:51820" /></label>
            <label className="field-label">Persistent keepalive<input min={0} max={65535} type="number" value={keepalive} onChange={(event) => setKeepalive(Number(event.target.value))} /></label>
            <label className="field-label">Allowed IPs<input className="mono" value={allowedIPs} onChange={(event) => setAllowedIPs(event.target.value)} placeholder="10.0.0.0/8, 192.168.0.0/16" /></label>
            <label className="field-label">DNS servers<input className="mono" value={dns} onChange={(event) => setDNS(event.target.value)} placeholder="10.0.0.53" /></label>
          </div>
          {pools.data?.length === 0 && <div className="alert danger compact-alert">Create an address pool before creating a VPN profile.</div>}
          {create.isError && <div className="alert danger compact-alert">{errorMessage(create.error)}</div>}
          <div className="form-actions"><button className="primary-button" disabled={!valid || create.isPending || pools.data?.length === 0} type="submit">{create.isPending ? 'Creating…' : 'Create profile'}</button></div>
        </form>
      )}
      {(profiles.isPending || pools.isPending) && <article className="panel loading-panel">Loading VPN profiles…</article>}
      {(profiles.isError || pools.isError) && <article className="alert danger">{errorMessage(profiles.error || pools.error)}</article>}
      {profiles.data && pools.data && (
        <article className="table-panel"><div className="table-scroll"><table className="data-table config-table profile-table"><thead><tr><th>Name</th><th>Endpoint</th><th>Address pool</th><th>Allowed IPs</th><th>Keepalive</th></tr></thead><tbody>
          {profiles.data.map((profile) => <tr key={profile.id}><td><div className="profile-name"><strong className="table-primary">{profile.name}</strong><span className="mono">{profile.server_public_key}</span></div></td><td className="mono">{profile.endpoint}</td><td>{poolNames.get(profile.address_pool_id) || profile.address_pool_id}</td><td className="mono">{profile.allowed_ips.join(', ')}</td><td>{profile.persistent_keepalive}s</td></tr>)}
          {profiles.data.length === 0 && <tr><td className="empty-cell" colSpan={5}>No VPN profiles configured yet.</td></tr>}
        </tbody></table></div></article>
      )}
    </section>
  )
}

function formatDate(value: string) {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(date)
}
