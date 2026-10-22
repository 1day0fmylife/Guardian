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
import { intlLocale, t } from './i18n'

function errorMessage(error: unknown) {
  if (axios.isAxiosError(error)) {
    const payload = error.response?.data as { error?: { message?: string } } | undefined
    return payload?.error?.message || error.message
  }
  return error instanceof Error ? error.message : t('Request failed')
}

function splitList(value: string) {
  return value.split(/[\n,]/).map((item) => item.trim()).filter(Boolean)
}

export function AddressPoolsPage() {
  const queryClient = useQueryClient()
  const principal = useQuery({ queryKey: ['me'], queryFn: getMe, staleTime: 30_000 })
  const pools = useQuery({ queryKey: ['address-pools'], queryFn: listAddressPools })
  const [name, setName] = React.useState('')
  const [cidr, setCIDR] = React.useState('10.89.0.0/22')
  const [gateway, setGateway] = React.useState('10.89.0.1')
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
      <div className="section-heading"><div><h2>{t('Address pools')}</h2><p>{t('IPv4 address ranges allocated to managed WireGuard peers.')}</p></div>{pools.data && <span className="count-chip">{t('Pools: {count}', { count: pools.data.length })}</span>}</div>
      {canCreate && (
        <form className="panel config-form" onSubmit={(event) => {
          event.preventDefault()
          if (!valid) return
          create.mutate({ name: name.trim(), cidr: cidr.trim(), gateway: gateway.trim(), dns_servers: splitList(dns) })
        }}>
          <div className="config-form-heading"><div><h2>{t('Create address pool')}</h2><p>{t('Guardian enforces unique leases from the selected CIDR.')}</p></div></div>
          <div className="config-form-grid">
            <label className="field-label">{t('Name')}<input value={name} onChange={(event) => setName(event.target.value)} placeholder={t('Office phones')} /></label>
            <label className="field-label">CIDR<input className="mono" value={cidr} onChange={(event) => setCIDR(event.target.value)} placeholder="10.89.0.0/22" /></label>
            <label className="field-label">{t('Gateway / reserved server IP')}<input className="mono" value={gateway} onChange={(event) => setGateway(event.target.value)} placeholder="10.89.0.1" /></label>
            <label className="field-label">{t('DNS servers')}<input className="mono" value={dns} onChange={(event) => setDNS(event.target.value)} placeholder="10.0.0.53, 10.0.0.54" /></label>
          </div>
          {create.isError && <div className="alert danger compact-alert">{errorMessage(create.error)}</div>}
          <div className="form-actions"><button className="primary-button" disabled={!valid || create.isPending} type="submit">{create.isPending ? t('Creating…') : t('Create pool')}</button></div>
        </form>
      )}
      {pools.isPending && <article className="panel loading-panel">{t('Loading address pools…')}</article>}
      {pools.isError && <article className="alert danger">{errorMessage(pools.error)}</article>}
      {pools.data && (
        <article className="table-panel"><div className="table-scroll"><table className="data-table config-table"><thead><tr><th>{t('Name')}</th><th>CIDR</th><th>{t('Gateway')}</th><th>DNS</th><th>{t('Updated')}</th></tr></thead><tbody>
          {pools.data.map((pool) => <tr key={pool.id}><td><strong className="table-primary">{pool.name}</strong></td><td className="mono">{pool.cidr}</td><td className="mono">{pool.gateway || '—'}</td><td className="mono">{pool.dns_servers?.join(', ') || '—'}</td><td>{formatDate(pool.updated_at)}</td></tr>)}
          {pools.data.length === 0 && <tr><td className="empty-cell" colSpan={5}>{t('Create an address pool before creating a VPN profile.')}</td></tr>}
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
      <div className="section-heading"><div><h2>{t('VPN profiles')}</h2><p>{t('Reusable WireGuard server parameters assigned during device enrollment.')}</p></div>{profiles.data && <span className="count-chip">{t('Profiles: {count}', { count: profiles.data.length })}</span>}</div>
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
          <div className="config-form-heading"><div><h2>{t('Create VPN profile')}</h2><p>{t('Only the WireGuard server public key is stored here. Device private keys remain on ArlanPhone.')}</p></div></div>
          <div className="config-form-grid profile-grid">
            <label className="field-label">{t('Name')}<input value={name} onChange={(event) => setName(event.target.value)} placeholder={t('Corporate WireGuard')} /></label>
            <label className="field-label">{t('Address pool')}<select value={poolID} onChange={(event) => setPoolID(event.target.value)}><option value="">{t('Select pool…')}</option>{pools.data?.map((pool) => <option key={pool.id} value={pool.id}>{pool.name} · {pool.cidr}</option>)}</select></label>
            <label className="field-label field-span-2">{t('Server public key')}<input className="mono" value={serverPublicKey} onChange={(event) => setServerPublicKey(event.target.value)} placeholder={t('WireGuard server public key')} /></label>
            <label className="field-label">{t('Endpoint')}<input className="mono" value={endpoint} onChange={(event) => setEndpoint(event.target.value)} placeholder="vpn.example.com:51820" /></label>
            <label className="field-label">{t('Persistent keepalive')}<input min={0} max={65535} type="number" value={keepalive} onChange={(event) => setKeepalive(Number(event.target.value))} /></label>
            <label className="field-label">{t('Allowed IPs')}<input className="mono" value={allowedIPs} onChange={(event) => setAllowedIPs(event.target.value)} placeholder="10.0.0.0/8, 192.168.0.0/16" /></label>
            <label className="field-label">{t('DNS servers')}<input className="mono" value={dns} onChange={(event) => setDNS(event.target.value)} placeholder="10.0.0.53" /></label>
          </div>
          {pools.data?.length === 0 && <div className="alert danger compact-alert">{t('Create an address pool before creating a VPN profile.')}</div>}
          {create.isError && <div className="alert danger compact-alert">{errorMessage(create.error)}</div>}
          <div className="form-actions"><button className="primary-button" disabled={!valid || create.isPending || pools.data?.length === 0} type="submit">{create.isPending ? t('Creating…') : t('Create profile')}</button></div>
        </form>
      )}
      {(profiles.isPending || pools.isPending) && <article className="panel loading-panel">{t('Loading VPN profiles…')}</article>}
      {(profiles.isError || pools.isError) && <article className="alert danger">{errorMessage(profiles.error || pools.error)}</article>}
      {profiles.data && pools.data && (
        <article className="table-panel"><div className="table-scroll"><table className="data-table config-table profile-table"><thead><tr><th>{t('Name')}</th><th>{t('Endpoint')}</th><th>{t('Address pool')}</th><th>{t('Allowed IPs')}</th><th>{t('Keepalive')}</th></tr></thead><tbody>
          {profiles.data.map((profile) => <tr key={profile.id}><td><div className="profile-name"><strong className="table-primary">{profile.name}</strong><span className="mono">{profile.server_public_key}</span></div></td><td className="mono">{profile.endpoint}</td><td>{poolNames.get(profile.address_pool_id) || profile.address_pool_id}</td><td className="mono">{profile.allowed_ips.join(', ')}</td><td>{t('{count} s', { count: profile.persistent_keepalive })}</td></tr>)}
          {profiles.data.length === 0 && <tr><td className="empty-cell" colSpan={5}>{t('No VPN profiles configured yet.')}</td></tr>}
        </tbody></table></div></article>
      )}
    </section>
  )
}

function formatDate(value: string) {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : new Intl.DateTimeFormat(intlLocale(), { dateStyle: 'medium', timeStyle: 'short' }).format(date)
}
