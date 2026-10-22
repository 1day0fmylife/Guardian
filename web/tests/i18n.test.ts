import { test, expect } from 'bun:test'
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { dictionaries, getLang, setLang, t, tState } from '../src/i18n'

const srcDir = join(import.meta.dir, '..', 'src')

function sourceKeys() {
  const keys = new Set<string>()
  for (const file of readdirSync(srcDir).filter((name) => /\.tsx?$/.test(name))) {
    for (const match of readFileSync(join(srcDir, file), 'utf8').matchAll(/\bt\(\s*'((?:[^'\\]|\\.)*)'/g)) keys.add(match[1])
  }
  return keys
}

test('every WebUI string has Russian and Kazakh translations', () => {
  const keys = sourceKeys()
  expect(keys.size).toBeGreaterThan(200)
  for (const [lang, dictionary] of Object.entries(dictionaries)) {
    const missing = [...keys].filter((key) => !(key in dictionary))
    expect({ lang, missing }).toEqual({ lang, missing: [] })
  }
})

test('ru and kk cover the same keys with the same placeholders', () => {
  const placeholders = (value: string) => [...value.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort()
  expect(Object.keys(dictionaries.kk).sort()).toEqual(Object.keys(dictionaries.ru).sort())
  for (const dictionary of Object.values(dictionaries)) {
    for (const [key, value] of Object.entries(dictionary)) expect({ key, p: placeholders(value) }).toEqual({ key, p: placeholders(key) })
  }
})

test('t switches language, interpolates and falls back to English', () => {
  const previous = getLang()
  try {
    setLang('ru')
    expect(t('Sign in')).toBe('Войти')
    expect(t('Page {page} of {pages}', { page: 1, pages: 3 })).toBe('Страница 1 из 3')
    expect(tState('succeeded')).toBe('Успешно')
    expect(t('Not translated')).toBe('Not translated')
    setLang('kk')
    expect(t('Sign in')).toBe('Кіру')
    setLang('en')
    expect(t('Users: {count}', { count: 2 })).toBe('Users: 2')
  } finally {
    setLang(previous)
  }
})
