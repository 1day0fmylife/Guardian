import React from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import axios from 'axios'
import {
  createAddressPool,
  createEnrollment,
  createVPNProfile,
  getMe,
  listAddressPools,
  listEnrollments,
  listVPNProfiles,
  type AddressPool,
  type IssuedEnrollment,
  type VPNProfile,
} from './api'
import { IssuedEnrollmentCard } from './enrollments'
import { t } from './i18n'
import './client-wizard.css'

// Step-by-step "add client" flow: network → VPN profile → device → provisioning.
// Each step either reuses an existing object or creates one; a created object is
// selected afterwards, so going back never creates a duplicate.

type Mode = 'existing' | 'new'
type StepId = 'network' | 'profile' | 'device' | 'provision'
const steps: StepId[] = ['network', 'profile', 'device', 'provision']

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

/** First 10.N.0.0/22 (N ≥ 88) whose second octet no existing 10.x pool uses. */
export function suggestPoolCIDR(pools: Pick<AddressPool, 'cidr'>[]) {
  const used = new Set(pools.map((pool) => pool.cidr.split('.')).filter((parts) => parts[0] === '10').map((parts) => Number(parts[1])))
  for (let octet = 88; octet < 255; octet++) if (!used.has(octet)) return { cidr: `10.${octet}.0.0/22`, gateway: `10.${octet}.0.1` }
  return { cidr: '', gateway: '' }
}

export function ClientWizardPage() {
  const queryClient = useQueryClient()
  const principal = useQuery({ queryKey: ['me'], queryFn: getMe, staleTime: 30_000 })
  const permissions = new Set(principal.data?.permissions ?? [])
  const canPoolsRead = permissions.has('pools.read')
  const canProfilesRead = permissions.has('profiles.read')
  const pools = useQuery({ queryKey: ['address-pools'], queryFn: listAddressPools, enabled: canPoolsRead })
  const profiles = useQuery({ queryKey: ['vpn-profiles'], queryFn: listVPNProfiles, enabled: canProfilesRead })

  const [step, setStep] = React.useState<StepId>('network')
  // Network
  const [poolMode, setPoolMode] = React.useState<Mode>('existing')
  const [poolId, setPoolId] = React.useState('')
  const [poolName, setPoolName] = React.useState('')
  const [poolCIDR, setPoolCIDR] = React.useState('')
  const [poolGateway, setPoolGateway] = React.useState('')
  const [poolDNS, setPoolDNS] = React.useState('')
  // Profile
  const [profileMode, setProfileMode] = React.useState<Mode>('existing')
  const [profileId, setProfileId] = React.useState('')
  const [profileName, setProfileName] = React.useState('')
  const [serverKey, setServerKey] = React.useState('')
  const [endpoint, setEndpoint] = React.useState('')
  const [allowedIPs, setAllowedIPs] = React.useState('0.0.0.0/0')
  const [profileDNS, setProfileDNS] = React.useState('')
  const [keepalive, setKeepalive] = React.useState(25)
  // Device
  const [label, setLabel] = React.useState('')
  const [deviceUuid, setDeviceUuid] = React.useState('')
  const [serial, setSerial] = React.useState('')
  const [mac, setMac] = React.useState('')
  const [ttl, setTTL] = React.useState(3600)
  // Result
  const [issued, setIssued] = React.useState<IssuedEnrollment | null>(null)

  // Defaults once data arrives: pick the first pool, or switch to "create" when there is none.
  React.useEffect(() => {
    if (!pools.data) return
    if (pools.data.length === 0) setPoolMode('new')
    else if (!poolId) setPoolId(pools.data[0].id)
    if (!poolCIDR) { const next = suggestPoolCIDR(pools.data); setPoolCIDR(next.cidr); setPoolGateway(next.gateway) }
  }, [pools.data, poolId, poolCIDR])

  const poolProfiles = React.useMemo(() => (profiles.data ?? []).filter((profile) => profile.address_pool_id === poolId), [profiles.data, poolId])
  // Entering the profile step: reuse a profile of this pool, otherwise prepare a new one
  // prefilled with the WireGuard server parameters already used elsewhere.
  React.useEffect(() => {
    if (step !== 'profile' || !profiles.data) return
    if (!poolProfiles.some((profile) => profile.id === profileId)) setProfileId(poolProfiles[0]?.id ?? '')
    if (poolProfiles.length === 0) setProfileMode('new')
    const template = profiles.data[0]
    if (template) {
      setServerKey((value) => value || template.server_public_key)
      setEndpoint((value) => value || template.endpoint)
    }
    const pool = pools.data?.find((item) => item.id === poolId)
    setProfileName((value) => value || (pool ? t('{pool} clients', { pool: pool.name }) : ''))
  }, [step, profiles.data, pools.data, poolProfiles, poolId, profileId])

  const createPool = useMutation({
    mutationFn: () => createAddressPool({ name: poolName.trim(), cidr: poolCIDR.trim(), gateway: poolGateway.trim(), dns_servers: splitList(poolDNS) }),
    onSuccess: async (pool) => {
      queryClient.setQueryData<AddressPool[]>(['address-pools'], (current) => [...(current ?? []), pool])
      await queryClient.invalidateQueries({ queryKey: ['address-pools'] })
      setPoolId(pool.id)
      setPoolMode('existing')
      setPoolName('')
      setStep('profile')
    },
  })
  const createProfile = useMutation({
    mutationFn: () => createVPNProfile({
      name: profileName.trim(), server_public_key: serverKey.trim(), endpoint: endpoint.trim(),
      allowed_ips: splitList(allowedIPs), dns_servers: splitList(profileDNS), persistent_keepalive: keepalive, address_pool_id: poolId,
    }),
    onSuccess: async (profile) => {
      queryClient.setQueryData<VPNProfile[]>(['vpn-profiles'], (current) => [...(current ?? []), profile])
      await queryClient.invalidateQueries({ queryKey: ['vpn-profiles'] })
      setProfileId(profile.id)
      setProfileMode('existing')
      setStep('device')
    },
  })
  const issue = useMutation({
    mutationFn: () => createEnrollment({
      name: label.trim(), profile_id: profileId, bound_device_uuid: deviceUuid.trim(),
      bound_serial_number: serial.trim(), bound_mac: mac.trim(), ttl_seconds: ttl,
    }),
    onSuccess: async (result) => {
      setIssued(result)
      await queryClient.invalidateQueries({ queryKey: ['enrollments'] })
    },
  })

  // While the provisioning data is shown, watch for the device to claim it.
  const enrollments = useQuery({ queryKey: ['enrollments'], queryFn: () => listEnrollments(100, 0), enabled: Boolean(issued), refetchInterval: issued ? 3_000 : false })
  const claimed = issued ? enrollments.data?.items.find((item) => item.id === issued.enrollment.id) : undefined
  const consumed = Boolean(claimed?.consumed_at)
  const revoked = Boolean(claimed?.revoked_at)
  React.useEffect(() => { if (consumed) void queryClient.invalidateQueries({ queryKey: ['devices'] }) }, [consumed, queryClient])

  if (principal.isPending) return <article className="panel loading-panel">{t('Loading…')}</article>
  if (!permissions.has('enrollment.create') || !canPoolsRead || !canProfilesRead) {
    return <article className="panel"><h2>{t('Add client')}</h2><p>{t('Adding a client requires the enrollment.create, pools.read and profiles.read permissions.')}</p></article>
  }

  const pool = pools.data?.find((item) => item.id === poolId)
  const profile = profiles.data?.find((item) => item.id === profileId)
  const stepIndex = steps.indexOf(step)
  const stepTitles: Record<StepId, string> = { network: t('Network'), profile: t('VPN profile'), device: t('Device'), provision: t('Connect device') }

  const reset = () => {
    setIssued(null); issue.reset(); setLabel(''); setDeviceUuid(''); setSerial(''); setMac(''); setStep('device')
  }

  const networkValid = poolMode === 'existing' ? Boolean(poolId) : poolName.trim() !== '' && poolCIDR.trim() !== ''
  const profileValid = profileMode === 'existing'
    ? Boolean(profileId)
    : profileName.trim() !== '' && serverKey.trim() !== '' && endpoint.trim() !== '' && splitList(allowedIPs).length > 0 && keepalive >= 0

  return (
    <section className="page-stack client-wizard">
      <div className="section-heading">
        <div><div className="eyebrow">{t('Provisioning')}</div><h2>{t('Add client')}</h2><p>{t('Set up the network and VPN profile, describe the device and hand it a one-time QR code. The WireGuard private key is generated on the device and never leaves it.')}</p></div>
      </div>

      <ol className="wizard-steps">
        {steps.map((id, index) => (
          <li key={id} className={index < stepIndex ? 'done' : index === stepIndex ? 'current' : undefined} aria-current={index === stepIndex ? 'step' : undefined}>
            <span className="wizard-step-number">{index < stepIndex ? <span className="material-symbols-rounded" aria-hidden="true">check</span> : index + 1}</span>
            <span>{stepTitles[id]}</span>
          </li>
        ))}
      </ol>

      {step === 'network' && (
        <form className="panel wizard-panel" onSubmit={(event) => {
          event.preventDefault()
          if (!networkValid) return
          if (poolMode === 'new') createPool.mutate()
          else setStep('profile')
        }}>
          <div><h2>{t('Which network will the client use?')}</h2><p>{t('The client gets a unique tunnel address from this address pool.')}</p></div>
          {pools.isPending && <p role="status">{t('Loading address pools…')}</p>}
          {pools.isError && <div className="alert danger">{errorMessage(pools.error)}</div>}
          {pools.data && <>
            <ModeChoice name="pool-mode" value={poolMode} onChange={setPoolMode} existingLabel={t('Use an existing pool')} newLabel={t('Create a new pool')} existingDisabled={pools.data.length === 0} newDisabled={!permissions.has('pools.create')} />
            {poolMode === 'existing'
              ? <label className="field-label">{t('Address pool')}<select value={poolId} onChange={(event) => setPoolId(event.target.value)}>{pools.data.map((item) => <option key={item.id} value={item.id}>{item.name} · {item.cidr}</option>)}</select></label>
              : <div className="wizard-grid">
                <label className="field-label">{t('Name')}<input required value={poolName} onChange={(event) => setPoolName(event.target.value)} placeholder={t('Office phones')} /></label>
                <label className="field-label">CIDR<input required className="mono" value={poolCIDR} onChange={(event) => setPoolCIDR(event.target.value)} placeholder="10.89.0.0/22" /></label>
                <label className="field-label">{t('Gateway / reserved server IP')}<input className="mono" value={poolGateway} onChange={(event) => setPoolGateway(event.target.value)} placeholder="10.89.0.1" /></label>
                <label className="field-label">{t('DNS servers')}<input className="mono" value={poolDNS} onChange={(event) => setPoolDNS(event.target.value)} placeholder="10.0.0.53" /></label>
                <p className="form-note field-span-2">{t('A /22 network holds 1,024 addresses.')}</p>
              </div>}
          </>}
          {createPool.isError && <div className="alert danger" role="alert">{errorMessage(createPool.error)}</div>}
          <WizardActions next={poolMode === 'new' ? (createPool.isPending ? t('Creating…') : t('Create pool and continue')) : t('Next')} nextDisabled={!networkValid || createPool.isPending} />
        </form>
      )}

      {step === 'profile' && (
        <form className="panel wizard-panel" onSubmit={(event) => {
          event.preventDefault()
          if (!profileValid) return
          if (profileMode === 'new') createProfile.mutate()
          else setStep('device')
        }}>
          <div><h2>{t('Which VPN server will the client connect to?')}</h2><p>{t('Profiles for pool {pool}.', { pool: pool ? `${pool.name} · ${pool.cidr}` : '—' })}</p></div>
          {profiles.isPending && <p role="status">{t('Loading VPN profiles…')}</p>}
          {profiles.isError && <div className="alert danger">{errorMessage(profiles.error)}</div>}
          {profiles.data && <>
            <ModeChoice name="profile-mode" value={profileMode} onChange={setProfileMode} existingLabel={t('Use an existing profile')} newLabel={t('Create a new profile')} existingDisabled={poolProfiles.length === 0} newDisabled={!permissions.has('profiles.create')} />
            {profileMode === 'existing'
              ? <label className="field-label">{t('VPN profile')}<select value={profileId} onChange={(event) => setProfileId(event.target.value)}>{poolProfiles.map((item) => <option key={item.id} value={item.id}>{item.name} · {item.endpoint}</option>)}</select></label>
              : <div className="wizard-grid">
                <label className="field-label">{t('Name')}<input required value={profileName} onChange={(event) => setProfileName(event.target.value)} placeholder={t('Corporate WireGuard')} /></label>
                <label className="field-label">{t('Endpoint')}<input required className="mono" value={endpoint} onChange={(event) => setEndpoint(event.target.value)} placeholder="vpn.example.com:51820" /></label>
                <label className="field-label field-span-2">{t('Server public key')}<input required className="mono" value={serverKey} onChange={(event) => setServerKey(event.target.value)} placeholder={t('WireGuard server public key')} /></label>
                <label className="field-label">{t('Allowed IPs')}<input required className="mono" value={allowedIPs} onChange={(event) => setAllowedIPs(event.target.value)} placeholder="10.0.0.0/8, 192.168.0.0/16" /></label>
                <label className="field-label">{t('DNS servers')}<input className="mono" value={profileDNS} onChange={(event) => setProfileDNS(event.target.value)} placeholder="10.0.0.53" /></label>
                <label className="field-label">{t('Persistent keepalive')}<input min={0} max={65535} type="number" value={keepalive} onChange={(event) => setKeepalive(Number(event.target.value))} /></label>
              </div>}
          </>}
          {createProfile.isError && <div className="alert danger" role="alert">{errorMessage(createProfile.error)}</div>}
          <WizardActions back={() => setStep('network')} next={profileMode === 'new' ? (createProfile.isPending ? t('Creating…') : t('Create profile and continue')) : t('Next')} nextDisabled={!profileValid || createProfile.isPending} />
        </form>
      )}

      {step === 'device' && (
        <form className="panel wizard-panel" onSubmit={(event) => { event.preventDefault(); if (profileId) setStep('provision') }}>
          <div><h2>{t('Describe the device')}</h2><p>{t('Binding is optional: a bound code can only be used by the matching ArlanPhone.')}</p></div>
          <div className="wizard-grid">
            <label className="field-label">{t('Label')}<input value={label} onChange={(event) => setLabel(event.target.value)} placeholder={t('Desk phone 1001')} /></label>
            <label className="field-label">{t('Valid for')}<select value={ttl} onChange={(event) => setTTL(Number(event.target.value))}>
              <option value={900}>{t('15 minutes')}</option>
              <option value={3600}>{t('1 hour')}</option>
              <option value={28800}>{t('8 hours')}</option>
              <option value={86400}>{t('24 hours')}</option>
            </select></label>
            <div className="form-section-label field-span-2">{t('Optional device binding')}</div>
            <label className="field-label">{t('Device UUID')}<input className="mono" value={deviceUuid} onChange={(event) => setDeviceUuid(event.target.value)} placeholder={t('Stable ArlanPhone UUID')} /></label>
            <label className="field-label">{t('Serial number')}<input className="mono" value={serial} onChange={(event) => setSerial(event.target.value)} placeholder={t('Serial number')} /></label>
            <label className="field-label">{t('Primary MAC')}<input className="mono" value={mac} onChange={(event) => setMac(event.target.value)} placeholder="00:11:22:33:44:55" /></label>
          </div>
          <WizardActions back={() => setStep('profile')} next={t('Next')} nextDisabled={!profileId} />
        </form>
      )}

      {step === 'provision' && !issued && (
        <article className="panel wizard-panel">
          <div><h2>{t('Check and issue')}</h2><p>{t('Issuing creates a one-time enrollment code. It is shown only once.')}</p></div>
          <dl className="wizard-summary">
            <dt>{t('Address pool')}</dt><dd>{pool ? `${pool.name} · ${pool.cidr}` : '—'}</dd>
            <dt>{t('VPN profile')}</dt><dd>{profile ? `${profile.name} · ${profile.endpoint}` : '—'}</dd>
            <dt>{t('Label')}</dt><dd>{label.trim() || t('Unnamed enrollment')}</dd>
            <dt>{t('Binding')}</dt><dd className="mono">{[deviceUuid, serial, mac].map((value) => value.trim()).filter(Boolean).join(' · ') || t('Any device')}</dd>
            <dt>{t('Valid for')}</dt><dd>{ttl === 900 ? t('15 minutes') : ttl === 3600 ? t('1 hour') : ttl === 28800 ? t('8 hours') : t('24 hours')}</dd>
          </dl>
          {issue.isError && <div className="alert danger" role="alert">{errorMessage(issue.error)}</div>}
          <div className="wizard-actions">
            <button className="secondary-button" type="button" onClick={() => setStep('device')} disabled={issue.isPending}>{t('Back')}</button>
            <button className="primary-button" type="button" onClick={() => issue.mutate()} disabled={issue.isPending || !profileId}>{issue.isPending ? t('Issuing…') : t('Issue enrollment')}</button>
          </div>
        </article>
      )}

      {step === 'provision' && issued && (
        <div className="enrollment-layout">
          <article className="panel wizard-panel">
            <div><h2>{t('Connect the device')}</h2></div>
            <ol className="wizard-instructions">
              <li>{t('On the ArlanPhone, open the Guardian enrollment screen.')}</li>
              <li>{t('Scan the QR code, or paste the provisioning URI or token.')}</li>
              <li>{t('The phone generates its WireGuard key and registers its public key with Guardian.')}</li>
            </ol>
            {consumed
              ? <div className="alert success" role="status"><span>{t('The device has enrolled.')}</span><Link className="secondary-button link-button" to="/devices">{t('Open devices')}</Link></div>
              : revoked
                ? <div className="alert danger" role="status">{t('This enrollment was revoked.')}</div>
                : <div className="wizard-waiting" role="status"><span className="material-symbols-rounded spin" aria-hidden="true">progress_activity</span>{t('Waiting for the device to enroll…')}</div>}
            <div className="wizard-actions">
              <Link className="secondary-button link-button" to="/enrollments">{t('All enrollments')}</Link>
              <button className="primary-button" type="button" onClick={reset}>{t('Add another client')}</button>
            </div>
          </article>
          {!consumed && !revoked && <IssuedEnrollmentCard issued={issued} dismiss={() => setIssued(null)} />}
        </div>
      )}
    </section>
  )
}

function ModeChoice({ name, value, onChange, existingLabel, newLabel, existingDisabled, newDisabled }: { name: string; value: Mode; onChange: (mode: Mode) => void; existingLabel: string; newLabel: string; existingDisabled: boolean; newDisabled: boolean }) {
  return (
    <div className="wizard-modes" role="radiogroup">
      <label className={value === 'existing' ? 'wizard-mode selected' : 'wizard-mode'}><input type="radio" name={name} checked={value === 'existing'} disabled={existingDisabled} onChange={() => onChange('existing')} />{existingLabel}</label>
      <label className={value === 'new' ? 'wizard-mode selected' : 'wizard-mode'}><input type="radio" name={name} checked={value === 'new'} disabled={newDisabled} onChange={() => onChange('new')} />{newLabel}</label>
    </div>
  )
}

function WizardActions({ back, next, nextDisabled }: { back?: () => void; next: string; nextDisabled: boolean }) {
  return (
    <div className="wizard-actions">
      {back && <button className="secondary-button" type="button" onClick={back}>{t('Back')}</button>}
      <button className="primary-button" type="submit" disabled={nextDisabled}>{next}</button>
    </div>
  )
}
