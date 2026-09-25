import React from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import axios from 'axios'
import {
  bootstrap,
  clearSession,
  getMe,
  getSetupStatus,
  hasSession,
  login,
  saveSession,
} from './api'

function errorMessage(error: unknown) {
  if (axios.isAxiosError(error)) {
    const payload = error.response?.data as { error?: { message?: string } } | undefined
    return payload?.error?.message || error.message
  }
  return error instanceof Error ? error.message : 'Request failed'
}

export function AuthGate({ children }: { children: React.ReactNode }) {
  const queryClient = useQueryClient()
  const setup = useQuery({ queryKey: ['setup-status'], queryFn: getSetupStatus, staleTime: 30_000 })
  const me = useQuery({
    queryKey: ['me'],
    queryFn: getMe,
    enabled: hasSession(),
    retry: false,
    staleTime: 30_000,
  })

  React.useEffect(() => {
    if (me.isError && axios.isAxiosError(me.error) && me.error.response?.status === 401) {
      clearSession()
      queryClient.removeQueries({ queryKey: ['me'] })
    }
  }, [me.error, me.isError, queryClient])

  if (setup.isPending || (hasSession() && me.isPending)) {
    return <AuthFrame><div className="auth-loading">Loading Guardian…</div></AuthFrame>
  }
  if (setup.isError) {
    return <AuthFrame><div className="alert danger">{errorMessage(setup.error)}</div></AuthFrame>
  }
  if (hasSession() && me.data) return <>{children}</>

  return <LoginForm bootstrapRequired={Boolean(setup.data?.bootstrap_required)} />
}

function LoginForm({ bootstrapRequired }: { bootstrapRequired: boolean }) {
  const queryClient = useQueryClient()
  const [username, setUsername] = React.useState('admin')
  const [displayName, setDisplayName] = React.useState('Administrator')
  const [password, setPassword] = React.useState('')

  const auth = useMutation({
    mutationFn: async () => bootstrapRequired
      ? bootstrap(username.trim(), displayName.trim(), password)
      : login(username.trim(), password),
    onSuccess: async (result) => {
      saveSession(result.token)
      await queryClient.invalidateQueries({ queryKey: ['me'] })
      await queryClient.invalidateQueries({ queryKey: ['setup-status'] })
    },
  })

  const canSubmit = username.trim() !== '' && password.length >= 1 && (!bootstrapRequired || displayName.trim() !== '')

  return (
    <AuthFrame>
      <form className="auth-card" onSubmit={(event) => { event.preventDefault(); if (canSubmit) auth.mutate() }}>
        <div className="auth-brand"><span className="material-symbols-rounded">shield</span>Guardian</div>
        <div>
          <div className="eyebrow">Secure access management</div>
          <h1>{bootstrapRequired ? 'Initialize Guardian' : 'Sign in'}</h1>
          <p>{bootstrapRequired ? 'Create the first superadmin account.' : 'Use your Guardian administrator account.'}</p>
        </div>
        <label className="field-label">Username<input autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} /></label>
        {bootstrapRequired && <label className="field-label">Display name<input autoComplete="name" value={displayName} onChange={(event) => setDisplayName(event.target.value)} /></label>}
        <label className="field-label">Password<input type="password" autoComplete={bootstrapRequired ? 'new-password' : 'current-password'} value={password} onChange={(event) => setPassword(event.target.value)} /></label>
        {auth.isError && <div className="alert danger">{errorMessage(auth.error)}</div>}
        <button className="primary-button" disabled={!canSubmit || auth.isPending} type="submit">
          {auth.isPending ? 'Please wait…' : bootstrapRequired ? 'Create administrator' : 'Sign in'}
        </button>
      </form>
    </AuthFrame>
  )
}

function AuthFrame({ children }: { children: React.ReactNode }) {
  return <div className="auth-page"><div className="auth-wrap">{children}</div></div>
}
