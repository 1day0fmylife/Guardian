import React from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import axios from 'axios'
import {
  api,
  apiErrorCode,
  bootstrap,
  changeOwnPassword,
  clearSession,
  getMe,
  getSetupStatus,
  hasSession,
  login,
  logout,
  saveSession,
} from './api'
import { t } from './i18n'
import { LanguageSelect } from './language-select'

function errorMessage(error: unknown) {
  if (axios.isAxiosError(error)) {
    const payload = error.response?.data as { error?: { message?: string } } | undefined
    return payload?.error?.message || error.message
  }
  return error instanceof Error ? error.message : t('Request failed')
}

export function AuthGate({ children }: { children: React.ReactNode }) {
  const queryClient = useQueryClient()
  const setup = useQuery({ queryKey: ['setup-status'], queryFn: getSetupStatus, staleTime: 30_000 })
  // Session presence is React state: sessionStorage changes do not re-render,
  // so a successful sign-in must flip this flag to enable the /me query.
  const [signedIn, setSignedIn] = React.useState(hasSession)
  const me = useQuery({
    queryKey: ['me'],
    queryFn: getMe,
    enabled: signedIn,
    retry: false,
    staleTime: 30_000,
  })

  // Any API call refused with password_change_required (e.g. after an
  // administrator reset in another tab) re-reads /me so the gate switches to
  // the forced-change screen instead of showing scattered 403 errors.
  React.useEffect(() => {
    const id = api.interceptors.response.use(undefined, (error) => {
      if (apiErrorCode(error) === 'password_change_required') void queryClient.invalidateQueries({ queryKey: ['me'] })
      return Promise.reject(error)
    })
    return () => api.interceptors.response.eject(id)
  }, [queryClient])

  React.useEffect(() => {
    if (me.isError && axios.isAxiosError(me.error) && me.error.response?.status === 401) {
      clearSession()
      setSignedIn(false)
      queryClient.removeQueries({ queryKey: ['me'] })
    }
  }, [me.error, me.isError, queryClient])

  if (setup.isPending || (signedIn && me.isPending)) {
    return <AuthFrame><div className="auth-loading">{t('Loading Guardian…')}</div></AuthFrame>
  }
  if (setup.isError) {
    return <AuthFrame><div className="alert danger">{errorMessage(setup.error)}</div></AuthFrame>
  }
  if (signedIn && me.data?.must_change_password) return <ForcedPasswordChange username={me.data.username} />
  if (signedIn && me.data) return <>{children}</>

  return <LoginForm bootstrapRequired={Boolean(setup.data?.bootstrap_required)} onSignedIn={() => setSignedIn(true)} />
}

function LoginForm({ bootstrapRequired, onSignedIn }: { bootstrapRequired: boolean; onSignedIn: () => void }) {
  const queryClient = useQueryClient()
  const [username, setUsername] = React.useState('')
  const [displayName, setDisplayName] = React.useState(() => t('Administrator'))
  const [password, setPassword] = React.useState('')

  const auth = useMutation({
    mutationFn: async () => bootstrapRequired
      ? bootstrap(username.trim(), displayName.trim(), password)
      : login(username.trim(), password),
    onSuccess: async (result) => {
      saveSession(result.token)
      queryClient.removeQueries({ queryKey: ['me'] })
      onSignedIn()
      await queryClient.invalidateQueries({ queryKey: ['setup-status'] })
    },
  })

  const canSubmit = username.trim() !== '' && password.length >= 1 && (!bootstrapRequired || displayName.trim() !== '')

  return (
    <AuthFrame>
      <form className="auth-card" onSubmit={(event) => { event.preventDefault(); if (canSubmit) auth.mutate() }}>
        <div className="auth-brand"><span className="material-symbols-rounded">shield</span>Guardian</div>
        <div>
          <div className="eyebrow">{t('Secure access management')}</div>
          <h1>{bootstrapRequired ? t('Initialize Guardian') : t('Sign in')}</h1>
          <p>{bootstrapRequired ? t('Create the first superadmin account. Deployments can instead set GUARDIAN_BOOTSTRAP_ADMIN_* in the environment.') : t('Use your Guardian account username and password.')}</p>
        </div>
        <label className="field-label">{t('Username')}<input autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} /></label>
        {bootstrapRequired && <label className="field-label">{t('Display name')}<input autoComplete="name" value={displayName} onChange={(event) => setDisplayName(event.target.value)} /></label>}
        <label className="field-label">{t('Password')}<input type="password" autoComplete={bootstrapRequired ? 'new-password' : 'current-password'} value={password} onChange={(event) => setPassword(event.target.value)} /></label>
        {auth.isError && <div className="alert danger">{errorMessage(auth.error)}</div>}
        <button className="primary-button" disabled={!canSubmit || auth.isPending} type="submit">
          {auth.isPending ? t('Please wait…') : bootstrapRequired ? t('Create administrator') : t('Sign in')}
        </button>
      </form>
    </AuthFrame>
  )
}

/** Shown instead of the application while the account must replace a
 * bootstrap or administrator-issued password; the API refuses everything else. */
export function ForcedPasswordChange({ username }: { username: string }) {
  const queryClient = useQueryClient()
  const signOut = useMutation({
    mutationFn: logout,
    onSettled: () => { clearSession(); queryClient.clear(); window.location.assign('/') },
  })
  return (
    <AuthFrame>
      <div className="auth-card">
        <div className="auth-brand"><span className="material-symbols-rounded">shield</span>Guardian</div>
        <div>
          <div className="eyebrow">{t('Signed in as {username}', { username })}</div>
          <h1>{t('Change your password')}</h1>
          <p>{t('Your password was issued by an administrator or deployment configuration. Choose a new personal password to continue.')}</p>
        </div>
        <ChangePasswordForm username={username} submitLabel={t('Change password and continue')} onChanged={async () => { await queryClient.invalidateQueries({ queryKey: ['me'] }) }} />
        <button className="secondary-button" type="button" disabled={signOut.isPending} onClick={() => signOut.mutate()}>{t('Sign out')}</button>
      </div>
    </AuthFrame>
  )
}

export const minPasswordLength = 12

/** Client-side mirror of the server policy; the server remains authoritative. */
export function passwordProblems(next: string, confirm: string, current: string, username: string) {
  const problems: string[] = []
  if (next.length < minPasswordLength) problems.push(t('At least {count} characters', { count: minPasswordLength }))
  if (next && next === current) problems.push(t('Must differ from the current password'))
  if (next && username && next.trim().toLowerCase() === username.trim().toLowerCase()) problems.push(t('Must not equal the username'))
  if (confirm && next !== confirm) problems.push(t('Confirmation does not match'))
  return problems
}

export function ChangePasswordForm({ username, submitLabel = t('Change password'), onChanged }: { username: string; submitLabel?: string; onChanged: () => Promise<void> | void }) {
  const [current, setCurrent] = React.useState('')
  const [next, setNext] = React.useState('')
  const [confirm, setConfirm] = React.useState('')
  const change = useMutation({
    mutationFn: () => changeOwnPassword(current, next),
    onSuccess: async () => { setCurrent(''); setNext(''); setConfirm(''); await onChanged() },
  })
  const problems = passwordProblems(next, confirm, current, username)
  const canSubmit = current !== '' && next !== '' && confirm === next && problems.length === 0
  return (
    <form className="password-form" onSubmit={(event) => { event.preventDefault(); if (canSubmit) change.mutate() }}>
      <input type="text" autoComplete="username" value={username} readOnly hidden />
      <label className="field-label">{t('Current password')}<input type="password" autoComplete="current-password" value={current} onChange={(event) => setCurrent(event.target.value)} /></label>
      <label className="field-label">{t('New password')}<input type="password" autoComplete="new-password" value={next} onChange={(event) => setNext(event.target.value)} aria-describedby="password-policy" /></label>
      <label className="field-label">{t('Confirm new password')}<input type="password" autoComplete="new-password" value={confirm} onChange={(event) => setConfirm(event.target.value)} /></label>
      <ul className="password-policy" id="password-policy">
        {[t('At least {count} characters', { count: minPasswordLength }), t('Must differ from the current password'), t('Must not equal the username')].map((rule) => <li key={rule} className={next && problems.includes(rule) ? 'unmet' : next ? 'met' : ''}>{rule}</li>)}
        {problems.includes(t('Confirmation does not match')) && <li className="unmet">{t('Confirmation does not match')}</li>}
      </ul>
      {change.isError && <div className="alert danger" role="alert">{errorMessage(change.error)}</div>}
      {change.isSuccess && <div className="alert success" role="status">{t('Password changed. Other sessions were signed out.')}</div>}
      <button className="primary-button" disabled={!canSubmit || change.isPending} type="submit">{change.isPending ? t('Please wait…') : submitLabel}</button>
    </form>
  )
}

function AuthFrame({ children }: { children: React.ReactNode }) {
  return <div className="auth-page"><div className="auth-wrap"><div className="auth-lang"><LanguageSelect /></div>{children}</div></div>
}
