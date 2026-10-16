import { test, expect } from 'bun:test'
import React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AuthGate, ForcedPasswordChange, passwordProblems } from '../src/auth'
import { UsersPage, generateTemporaryPassword } from '../src/admin'
import { api, apiErrorCode, changeOwnPassword, listUsers, sessionTokenKey } from '../src/api'

function storage(token: string | null) {
 globalThis.sessionStorage = { getItem: (key: string) => key === sessionTokenKey ? token : null, setItem() {}, removeItem() {} } as unknown as Storage
}
function client() { return new QueryClient({ defaultOptions: { queries: { staleTime: Infinity, retry: false } } }) }

test('password policy mirrors the server rules', () => {
 expect(passwordProblems('short', 'short', 'old', 'admin')).toContain('At least 12 characters')
 expect(passwordProblems('same password!!', 'same password!!', 'same password!!', 'admin')).toContain('Must differ from the current password')
 expect(passwordProblems('administrator', 'administrator', 'x', 'Administrator')).toContain('Must not equal the username')
 expect(passwordProblems('a good new password', 'different', 'x', 'admin')).toContain('Confirmation does not match')
 expect(passwordProblems('a good new password', 'a good new password', 'x', 'admin')).toEqual([])
})

test('a session flagged must_change_password only gets the forced change screen', () => {
 storage('gdn_s_test')
 const c = client()
 c.setQueryData(['setup-status'], { bootstrap_required: false })
 c.setQueryData(['me'], { user_id: 'u1', username: 'admin', display_name: 'Admin', roles: ['superadmin'], permissions: ['devices.read'], must_change_password: true })
 const html = renderToStaticMarkup(<QueryClientProvider client={c}><AuthGate><div>application shell</div></AuthGate></QueryClientProvider>)
 expect(html).toContain('Change your password')
 expect(html).toContain('Sign out')
 expect(html).not.toContain('application shell')
 c.setQueryData(['me'], { user_id: 'u1', username: 'admin', display_name: 'Admin', roles: ['superadmin'], permissions: [], must_change_password: false })
 expect(renderToStaticMarkup(<QueryClientProvider client={c}><AuthGate><div>application shell</div></AuthGate></QueryClientProvider>)).toContain('application shell')
})

test('signed-out users see a username/password form, not a token prompt', () => {
 storage(null)
 const c = client()
 c.setQueryData(['setup-status'], { bootstrap_required: false })
 const html = renderToStaticMarkup(<QueryClientProvider client={c}><AuthGate><div>app</div></AuthGate></QueryClientProvider>)
 expect(html).toContain('autoComplete="username"')
 expect(html).toContain('type="password"')
 expect(html).toContain('Sign in')
 expect(html).not.toContain('gdn_s_')
})

test('forced change form requires the current password and new-password autocomplete', () => {
 const html = renderToStaticMarkup(<QueryClientProvider client={client()}><ForcedPasswordChange username="admin" /></QueryClientProvider>)
 expect(html).toContain('Current password')
 expect(html).toContain('autoComplete="new-password"')
 expect(html).toContain('At least 12 characters')
})

async function captureRequest(run: () => Promise<unknown>) {
 const old = api.defaults.adapter
 let seen: { url?: string; params?: Record<string, unknown>; data?: string } = {}
 api.defaults.adapter = async config => { seen = { url: config.url, params: config.params, data: config.data }; return { data: { items: [], total: 0, limit: 25, offset: 0 }, status: 200, statusText: 'OK', headers: {}, config } }
 storage(null)
 try { await run() } finally { api.defaults.adapter = old }
 return seen
}

test('user listing sends server-side pagination, filters and sort', async () => {
 const seen = await captureRequest(() => listUsers({ limit: 25, offset: 50, q: 'ali', status: 'disabled', role: 'auditor', sort: 'created_at', desc: true }))
 expect(seen.url).toBe('/users')
 expect(seen.params).toEqual({ limit: 25, offset: 50, q: 'ali', status: 'disabled', role: 'auditor', sort: '-created_at' })
 const plain = await captureRequest(() => listUsers({ limit: 10, offset: 0, q: '', status: '', role: '', sort: 'username', desc: false }))
 expect(plain.params).toEqual({ limit: 10, offset: 0, sort: 'username' })
})

test('password change posts current and new password only', async () => {
 const seen = await captureRequest(() => changeOwnPassword('old secret value', 'new secret value'))
 expect(seen.url).toBe('/auth/password')
 expect(JSON.parse(seen.data ?? '{}')).toEqual({ current_password: 'old secret value', new_password: 'new secret value' })
})

test('api error codes are exposed for password_change_required handling', () => {
 const error = Object.assign(new Error('forbidden'), { isAxiosError: true, response: { status: 403, data: { error: { code: 'password_change_required' } } } })
 expect(apiErrorCode(error)).toBe('password_change_required')
 expect(apiErrorCode(new Error('x'))).toBeUndefined()
})

function renderUsers(permissions: string[]) {
 const c = client()
 c.setQueryData(['me'], { user_id: 'u1', username: 'root', display_name: 'Root', roles: [], permissions })
 c.setQueryData(['admin-roles'], [{ id: 'viewer', name: 'viewer', description: 'Read-only', system: true, permissions: ['devices.read'] }, { id: 'auditor', name: 'auditor', description: 'Audit', system: true, permissions: ['audit.read'] }])
 c.setQueryData(['admin-users', { limit: 25, offset: 0, q: '', status: '', role: '', sort: 'username', desc: false }], {
  total: 60, limit: 25, offset: 0,
  items: [
   { id: 'u1', username: 'root', display_name: 'Root', disabled: false, roles: ['superadmin'], created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-01T00:00:00Z' },
   { id: 'u2', username: 'alice', display_name: 'Alice', disabled: false, must_change_password: true, roles: ['viewer'], created_at: '2026-10-02T00:00:00Z', updated_at: '2026-10-02T00:00:00Z' },
   { id: 'u3', username: 'bob', display_name: 'Bob', disabled: true, roles: ['auditor'], created_at: '2026-10-03T00:00:00Z', updated_at: '2026-10-03T00:00:00Z' },
  ],
 })
 return renderToStaticMarkup(<QueryClientProvider client={c}><UsersPage /></QueryClientProvider>)
}

test('users table is server-paginated with status, filters and sortable headers', () => {
 const html = renderUsers(['users.read'])
 expect(html).toContain('60 users')
 expect(html).toContain('1–25 of 60')
 expect(html).toContain('Page 1 of 3')
 expect(html).toContain('Password change pending')
 expect(html).toContain('Locked')
 expect(html).toContain('aria-sort="ascending"')
 expect(html).toContain('Username or display name')
 expect(html).not.toContain('Create user')
 expect(html).not.toContain('>Manage</button>')
})

test('user mutations follow users.create and users.update permissions', () => {
 const create = renderUsers(['users.read', 'users.create'])
 expect(create).toContain('Create user')
 expect(create).toContain('Temporary password')
 expect(create).not.toContain('>Manage</button>')
 const update = renderUsers(['users.read', 'users.update'])
 expect(update).not.toContain('Create user')
 expect(update).toContain('>Manage</button>')
})

test('temporary passwords satisfy the length policy and differ', () => {
 const first = generateTemporaryPassword()
 expect(first.length).toBeGreaterThanOrEqual(12)
 expect(generateTemporaryPassword()).not.toBe(first)
})
