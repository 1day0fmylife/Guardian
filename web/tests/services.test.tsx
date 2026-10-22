import { test, expect } from 'bun:test'
import React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { DeviceServices } from '../src/services'
import { api, updateService, type ServiceDefinition } from '../src/api'

const service: ServiceDefinition = { id: 'sunkardav', revision: 2, display_name: 'SunkarDAV', internal_dns_name: 'dav.internal', protocol: 'https', port: 443, tls_policy: 'required', enabled: false, allowed_scopes: ['device'] }
function render(permissions: string[]) {
 const client = new QueryClient({ defaultOptions: { queries: { staleTime: Infinity, retry: false } } })
 client.setQueryData(['services'], [service])
 client.setQueryData(['service-policy', 'device-a'], { device_id: 'device-a', access_state: 'active', revision: 4, scopes: { tenant_id: '', site_id: '', group_ids: [] }, services: [{ service_id: service.id, display_name: service.display_name, service_revision: 2, allowed: false, reason: 'no_grant' }] })
 client.setQueryData(['device-audit', 'device-a', 0], { items: [], total: 0 })
 return renderToStaticMarkup(<QueryClientProvider client={client}><DeviceServices deviceId="device-a" permissions={new Set(permissions)} /></QueryClientProvider>)
}
test('viewer neither fetches nor displays service administration or audit', () => {
 expect(render(['devices.read'])).toBe('')
})
test('operator can inspect blocked policy but cannot edit or read audit', () => {
 const html = render(['devices.read', 'services.read'])
 expect(html).toContain('Blocked')
 expect(html).toContain('Read only')
 expect(html).not.toContain('>Allow</button>')
 expect(html).not.toContain('Save catalog revision')
 expect(html).not.toContain('Device audit timeline')
})
test('admin sees independent override actions; audit permission remains separate', () => {
 const html = render(['services.read', 'services.manage'])
 for (const label of ['Allow', 'Deny', 'Inherit']) expect(html).toContain(`>${label}</button>`)
 expect(html).toContain('No access is granted by default')
 expect(html).not.toContain('Device audit timeline')
 expect(render(['audit.read'])).toContain('Device audit timeline')
})
test('catalog update explicitly excludes response-only and secret fields', async () => {
 let body: Record<string, unknown> = {}
 const old = api.defaults.adapter
 api.defaults.adapter = async config => { body = JSON.parse(config.data); return { data: {}, status: 200, statusText: 'OK', headers: {}, config } }
 // Request interceptor uses sessionStorage only for authentication.
 globalThis.sessionStorage = { getItem: () => null } as unknown as Storage
 try {
  await updateService({ ...service, created_at: 'extra', token: 'canary' } as ServiceDefinition)
  expect(body.expected_revision).toBe(2)
  expect(body.enabled).toBe(false)
  expect(body).not.toHaveProperty('token')
  expect(body).not.toHaveProperty('created_at')
  expect(body).not.toHaveProperty('id')
 } finally { api.defaults.adapter = old }
})

import { EnrollmentsPage } from '../src/enrollments'
import { renderWithRouter } from './render'
function renderEnrollments(permissions: string[]) {
 const client = new QueryClient({ defaultOptions: { queries: { staleTime: Infinity, retry: false } } })
 client.setQueryData(['me'], { permissions })
 client.setQueryData(['enrollments'], { items: [{ id: 'e1', name: 'Active', profile_id: 'p1', expires_at: '2099-01-01T00:00:00Z', created_at: '2026-10-10T00:00:00Z' }], total: 1 })
 client.setQueryData(['vpn-profiles'], [])
 return renderWithRouter(client, () => <EnrollmentsPage />)
}
test('read-only enrollment roles cannot issue or revoke tokens', async () => {
 const html = await renderEnrollments(['enrollment.read'])
 expect(html).not.toContain('Add client')
 expect(html).not.toContain('Issue enrollment')
 expect(html).not.toContain('>Revoke</button>')
 expect(html).not.toContain('Provisioning output')
})
test('enrollment create and revoke permissions are independent', async () => {
 const create = await renderEnrollments(['enrollment.read', 'enrollment.create', 'profiles.read'])
 expect(create).toContain('Add client')
 expect(create).toContain('Issue enrollment')
 expect(create).not.toContain('>Revoke</button>')
 const revoke = await renderEnrollments(['enrollment.read', 'enrollment.revoke'])
 expect(revoke).not.toContain('Issue enrollment')
 expect(revoke).toContain('>Revoke</button>')
})
