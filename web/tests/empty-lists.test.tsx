import { test, expect } from 'bun:test'
import React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { CommandsPage } from '../src/admin'
import { EnrollmentsPage } from '../src/enrollments'
import { api } from '../src/api'
import { getLang, setLang } from '../src/i18n'

function client() { return new QueryClient({ defaultOptions: { queries: { staleTime: Infinity, retry: false } } }) }

test('a null items array from the API is normalized to an empty list', async () => {
  const old = api.defaults.adapter
  api.defaults.adapter = async (config) => ({ data: { items: null, total: 0, limit: 50, offset: 0 }, status: 200, statusText: 'OK', headers: {}, config })
  try {
    const response = await api.get('/enrollments')
    expect(response.data.items).toEqual([])
  } finally { api.defaults.adapter = old }
})

test('empty enrollments and commands pages render in Russian', () => {
  const previous = getLang()
  setLang('ru')
  try {
    const c = client()
    c.setQueryData(['me'], { permissions: ['enrollment.read', 'enrollment.create', 'profiles.read'] })
    c.setQueryData(['enrollments'], { items: [], total: 0, limit: 100, offset: 0 })
    c.setQueryData(['vpn-profiles'], [])
    c.setQueryData(['commands-global'], { items: [], total: 0, limit: 100, offset: 0 })
    const enrollments = renderToStaticMarkup(<QueryClientProvider client={c}><EnrollmentsPage /></QueryClientProvider>)
    expect(enrollments).toContain('Регистрации ещё не выдавались.')
    expect(enrollments).toContain('Выдать регистрацию')
    const commands = renderToStaticMarkup(<QueryClientProvider client={c}><CommandsPage /></QueryClientProvider>)
    expect(commands).toContain('Команд: 0')
  } finally { setLang(previous) }
})
