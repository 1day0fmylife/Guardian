import React from 'react'
import { QRCodeSVG } from 'qrcode.react'
import { getMe } from './api'
import { Link } from '@tanstack/react-router'
import { intlLocale, t } from './i18n'
import './services.css'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import axios from 'axios'
import {
  createEnrollment,
  listEnrollments,
  listVPNProfiles,
  revokeEnrollment,
  type Enrollment,
  type EnrollmentCreate,
  type IssuedEnrollment,
} from './api'

function errorMessage(error: unknown) {
  if (axios.isAxiosError(error)) {
    const payload = error.response?.data as { error?: { message?: string } } | undefined
    return payload?.error?.message || error.message
  }
  return error instanceof Error ? error.message : t('Request failed')
}

export function EnrollmentsPage() {
  const queryClient = useQueryClient()
  const principal = useQuery({ queryKey: ['me'], queryFn: getMe })
  const canCreate = Boolean(principal.data?.permissions.includes('enrollment.create'))
  const canRevoke = Boolean(principal.data?.permissions.includes('enrollment.revoke'))
  const profiles = useQuery({ queryKey: ['vpn-profiles'], queryFn: listVPNProfiles, staleTime: 30_000, enabled: canCreate && Boolean(principal.data?.permissions.includes('profiles.read')) })
  const enrollments = useQuery({ queryKey: ['enrollments'], queryFn: () => listEnrollments(100, 0), refetchInterval: 15_000 })
  const [profileId, setProfileId] = React.useState('')
  const [name, setName] = React.useState('')
  const [deviceUuid, setDeviceUuid] = React.useState('')
  const [serial, setSerial] = React.useState('')
  const [mac, setMac] = React.useState('')
  const [ttl, setTTL] = React.useState(900)
  const [issued, setIssued] = React.useState<IssuedEnrollment | null>(null)

  React.useEffect(() => {
    if (!issued) return
    const timer = window.setTimeout(() => setIssued(null), Math.max(0, new Date(issued.enrollment.expires_at).getTime() - Date.now()))
    return () => window.clearTimeout(timer)
  }, [issued])
  React.useEffect(() => {
    if (!issued) return
    const current = enrollments.data?.items.find(item => item.id === issued.enrollment.id)
    if (current?.consumed_at || current?.revoked_at || !canCreate) setIssued(null)
  }, [issued, enrollments.data, canCreate])
  React.useEffect(() => {
    if (!profileId && profiles.data?.length) setProfileId(profiles.data[0].id)
  }, [profileId, profiles.data])

  const create = useMutation({
    mutationKey: ['issue-enrollment'],
    mutationFn: (input: EnrollmentCreate) => createEnrollment(input),
    onSuccess: async (result) => {
      setIssued(result)
      create.reset()
      for (const mutation of queryClient.getMutationCache().getAll()) {
        if (mutation.options.mutationKey?.[0] === 'issue-enrollment') queryClient.getMutationCache().remove(mutation)
      }
      setName('')
      setDeviceUuid('')
      setSerial('')
      setMac('')
      await queryClient.invalidateQueries({ queryKey: ['enrollments'] })
    },
  })
  const revoke = useMutation({
    mutationFn: revokeEnrollment,
    onSuccess: async (_, id) => {
      if (issued?.enrollment.id === id) setIssued(null)
      await queryClient.invalidateQueries({ queryKey: ['enrollments'] })
    },
  })

  const submit = (event: React.FormEvent) => {
    event.preventDefault()
    if (!profileId || !canCreate) return
    setIssued(null)
    create.mutate({
      name: name.trim(),
      profile_id: profileId,
      bound_device_uuid: deviceUuid.trim(),
      bound_serial_number: serial.trim(),
      bound_mac: mac.trim(),
      ttl_seconds: ttl,
    })
  }

  return (
    <section className="page-stack">
      <div className="section-heading">
        <div><div className="eyebrow">{t('Provisioning')}</div><h2>{t('Enrollments')}</h2><p>{t('Issue short-lived, single-use enrollment credentials for ArlanPhone devices.')}</p></div>
        <div className="heading-actions">{enrollments.data && <span className="count-chip">{t('Issued: {count}', { count: enrollments.data.total })}</span>}{canCreate && <Link className="primary-button link-button" to="/clients/new"><span className="material-symbols-rounded" aria-hidden="true">person_add</span>{t('Add client')}</Link>}</div>
      </div>

      <div className="enrollment-layout">
        {canCreate && <article className="panel">
          <div className="card-title"><span className="material-symbols-rounded">qr_code_2</span><h2>{t('New enrollment')}</h2></div>
          <form className="form-grid" onSubmit={submit}>
            <label className="field-label">{t('VPN profile')}
              <select value={profileId} onChange={(event) => setProfileId(event.target.value)} disabled={profiles.isPending || create.isPending}>
                {profiles.data?.map((profile) => <option key={profile.id} value={profile.id}>{profile.name} · {profile.endpoint}</option>)}
              </select>
            </label>
            <label className="field-label">{t('Label')} <input placeholder={t('Desk phone 1001')} value={name} onChange={(event) => setName(event.target.value)} /></label>
            <label className="field-label">{t('Valid for')}
              <select value={ttl} onChange={(event) => setTTL(Number(event.target.value))}>
                <option value={900}>{t('15 minutes')}</option>
                <option value={3600}>{t('1 hour')}</option>
                <option value={28800}>{t('8 hours')}</option>
                <option value={86400}>{t('24 hours')}</option>
              </select>
            </label>
            <div className="form-section-label">{t('Optional device binding')}</div>
            <label className="field-label">{t('Device UUID')} <input className="mono" placeholder={t('Stable ArlanPhone UUID')} value={deviceUuid} onChange={(event) => setDeviceUuid(event.target.value)} /></label>
            <label className="field-label">{t('Serial number')} <input className="mono" placeholder={t('Serial number')} value={serial} onChange={(event) => setSerial(event.target.value)} /></label>
            <label className="field-label">{t('Primary MAC')} <input className="mono" placeholder="00:11:22:33:44:55" value={mac} onChange={(event) => setMac(event.target.value)} /></label>
            {profiles.data?.length === 0 && <div className="alert danger">{t('Create a VPN profile before issuing an enrollment.')}</div>}
            {profiles.isError && <div className="alert danger">{errorMessage(profiles.error)}</div>}
            {create.isError && <div className="alert danger">{errorMessage(create.error)}</div>}
            <button className="primary-button" type="submit" disabled={!profileId || create.isPending}>{create.isPending ? t('Issuing…') : t('Issue enrollment')}</button>
          </form>
        </article>}
        {canCreate && <IssuedEnrollmentCard issued={issued} dismiss={() => setIssued(null)} />}
      </div>

      {revoke.isError && <div role="alert" className="alert danger">{errorMessage(revoke.error)}</div>}
      <article className="table-panel">
        <div className="table-header"><div><div className="eyebrow">{t('History')}</div><h2>{t('Enrollment credentials')}</h2></div></div>
        {enrollments.isPending ? <div className="table-state">{t('Loading…')}</div> : enrollments.isError ? <div className="table-state danger-text">{errorMessage(enrollments.error)}</div> : (
          <div className="table-scroll"><table className="data-table enrollment-table">
            <thead><tr><th>{t('Enrollment')}</th><th>{t('Status')}</th><th>{t('Binding')}</th><th>{t('Expires')}</th><th /></tr></thead>
            <tbody>
              {enrollments.data?.items.map((item) => <EnrollmentRow key={item.id} enrollment={item} revoking={revoke.isPending} onRevoke={canRevoke ? (id) => revoke.mutate(id) : undefined} />)}
              {enrollments.data?.items.length === 0 && <tr><td className="empty-cell" colSpan={5}>{t('No enrollments issued yet.')}</td></tr>}
            </tbody>
          </table></div>
        )}
      </article>
    </section>
  )
}

export function IssuedEnrollmentCard({ issued, dismiss }: { issued: IssuedEnrollment | null; dismiss: () => void }) {
  const [copyError, setCopyError] = React.useState('')
  const [copied, setCopied] = React.useState('')
  React.useEffect(() => setCopied(''), [issued])
  if (!issued) {
    return <article className="panel issued-placeholder"><span className="material-symbols-rounded">phonelink_setup</span><div><h2>{t('Provisioning output')}</h2><p>{t('After issuing an enrollment, its one-time token and Guardian provisioning URI will appear here.')}</p></div></article>
  }
  const copy = async (kind: string, value: string) => {
    try { await navigator.clipboard.writeText(value); setCopied(kind); setCopyError('') }
    catch { setCopyError(t('Clipboard unavailable. Select and copy the provisioning data manually.')) }
  }
  return <article className="panel issued-card">
    <div><div className="eyebrow">{t('Issued once')}</div><h2>{t('Copy provisioning data now')}</h2><p>{t('The token is shown in this response only. Guardian stores its hash, not the plaintext token.')}</p></div>
    <QRCodeSVG className="provisioning-qr" value={issued.provisioning_uri} size={320} marginSize={4} level="M" title={t('One-time Guardian enrollment URI')} />
    <p>{t('Expires: {date}', { date: formatDate(issued.enrollment.expires_at) })}</p>
    <button type="button" className="secondary-button" onClick={dismiss}>{t('Hide provisioning data')}</button>
    {copyError && <p role="alert">{copyError}</p>}
    <div className="secret-block"><span>{t('Enrollment token')}</span><code>{issued.token}</code><button type="button" className="secondary-button" onClick={() => void copy('token', issued.token)}>{copied === 'token' ? t('Copied') : t('Copy token')}</button></div>
    <div className="secret-block"><span>{t('Provisioning URI / QR payload')}</span><code>{issued.provisioning_uri}</code><button type="button" className="secondary-button" onClick={() => void copy('uri', issued.provisioning_uri)}>{copied === 'uri' ? t('Copied') : t('Copy URI')}</button></div>
    <div className="provisioning-note"><span className="material-symbols-rounded">security</span><span>{t('ArlanPhone can paste or scan this URI. Its WireGuard private key is still generated locally on the phone.')}</span></div>
  </article>
}

function EnrollmentRow({ enrollment, revoking, onRevoke }: { enrollment: Enrollment; revoking: boolean; onRevoke?: (id: string) => void }) {
  const state = enrollmentState(enrollment)
  const binding = enrollment.bound_device_uuid || enrollment.bound_serial_number || enrollment.bound_mac || t('Any device')
  return <tr>
    <td><div className="device-name"><strong>{enrollment.name || t('Unnamed enrollment')}</strong><span>{enrollment.id}</span></div></td>
    <td><span className={`badge ${state.tone}`}><span className="dot" />{state.label}</span></td>
    <td className="mono">{binding}</td>
    <td>{formatDate(enrollment.expires_at)}</td>
    <td className="table-action">{state.revocable && onRevoke && <button className="secondary-button compact" type="button" disabled={revoking} onClick={() => onRevoke(enrollment.id)}>{t('Revoke')}</button>}</td>
  </tr>
}

function enrollmentState(enrollment: Enrollment) {
  if (enrollment.revoked_at) return { label: t('Revoked'), tone: 'danger', revocable: false }
  if (enrollment.consumed_at) return { label: t('Consumed'), tone: 'neutral', revocable: false }
  if (new Date(enrollment.expires_at).getTime() <= Date.now()) return { label: t('Expired'), tone: 'neutral', revocable: false }
  return { label: t('Active'), tone: 'ok', revocable: true }
}

function formatDate(value: string) {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : new Intl.DateTimeFormat(intlLocale(), { dateStyle: 'medium', timeStyle: 'short' }).format(date)
}
