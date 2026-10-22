import { test, expect } from 'bun:test'
import React from 'react'
import { QueryClient } from '@tanstack/react-query'
import { ClientWizardPage, suggestPoolCIDR } from '../src/client-wizard'
import { getLang, setLang } from '../src/i18n'
import { renderWithRouter } from './render'

function client(permissions: string[]) {
  const c = new QueryClient({ defaultOptions: { queries: { staleTime: Infinity, retry: false } } })
  c.setQueryData(['me'], { permissions })
  c.setQueryData(['address-pools'], [{ id: 'p1', name: 'Default', cidr: '10.88.0.0/22', gateway: '10.88.0.1', created_at: '', updated_at: '' }])
  c.setQueryData(['vpn-profiles'], [])
  return c
}
const full = ['enrollment.create', 'pools.read', 'pools.create', 'profiles.read', 'profiles.create']

test('suggested pool is the next free 10.x /22', () => {
  expect(suggestPoolCIDR([])).toEqual({ cidr: '10.88.0.0/22', gateway: '10.88.0.1' })
  expect(suggestPoolCIDR([{ cidr: '10.88.0.0/22' }, { cidr: '10.89.0.0/22' }, { cidr: '192.168.0.0/24' }])).toEqual({ cidr: '10.90.0.0/22', gateway: '10.90.0.1' })
})

test('wizard starts at the network step with all four steps listed', async () => {
  const html = await renderWithRouter(client(full), () => <ClientWizardPage />)
  for (const text of ['Network', 'VPN profile', 'Device', 'Connect device', 'Which network will the client use?', 'Default · 10.88.0.0/22']) expect(html).toContain(text)
  expect(html).toContain('aria-current="step"')
})

test('wizard explains missing permissions instead of showing the form', async () => {
  const html = await renderWithRouter(client(['enrollment.read']), () => <ClientWizardPage />)
  expect(html).toContain('enrollment.create, pools.read and profiles.read')
  expect(html).not.toContain('Which network will the client use?')
})

test('pool creation is unavailable without pools.create', async () => {
  const html = await renderWithRouter(client(['enrollment.create', 'pools.read', 'profiles.read']), () => <ClientWizardPage />)
  expect(html).toMatch(/<input type="radio"[^>]*disabled=""[^>]*\/>Create a new pool/)
})

test('wizard renders in Kazakh', async () => {
  const previous = getLang()
  setLang('kk')
  try {
    const html = await renderWithRouter(client(full), () => <ClientWizardPage />)
    expect(html).toContain('Клиент қай желіні пайдаланады?')
  } finally { setLang(previous) }
})
