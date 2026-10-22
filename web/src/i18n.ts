import React from 'react'
import { kk } from './locales/kk'
import { ru } from './locales/ru'

// English source strings are the message keys; ru/kk map them to translations.
// A missing translation falls back to English (tests/i18n.test.ts guards coverage).

export type Lang = 'en' | 'ru' | 'kk'

export const languages: ReadonlyArray<{ code: Lang; label: string; short: string }> = [
  { code: 'en', label: 'English', short: 'EN' },
  { code: 'ru', label: 'Русский', short: 'RU' },
  { code: 'kk', label: 'Қазақша', short: 'KK' },
]

export const dictionaries: Record<Exclude<Lang, 'en'>, Record<string, string>> = { ru, kk }

const storageKey = 'guardian.lang'
const intlLocales: Record<Lang, string | undefined> = { en: undefined, ru: 'ru-RU', kk: 'kk-KZ' }

function isLang(value: unknown): value is Lang {
  return value === 'en' || value === 'ru' || value === 'kk'
}

function detectLang(): Lang {
  try {
    const saved = localStorage.getItem(storageKey)
    if (isLang(saved)) return saved
  } catch { /* storage unavailable */ }
  try {
    for (const tag of navigator.languages ?? [navigator.language]) {
      const base = tag?.toLowerCase().split('-')[0]
      if (base === 'kk' || base === 'ru') return base
      if (base === 'en') return 'en'
    }
  } catch { /* no navigator (tests, SSR) */ }
  return 'en'
}

let current: Lang = detectLang()
const listeners = new Set<() => void>()

function applyDocumentLang(lang: Lang) {
  if (typeof document !== 'undefined') document.documentElement.lang = lang
}
applyDocumentLang(current)

export function getLang(): Lang {
  return current
}

export function setLang(lang: Lang) {
  if (lang === current) return
  current = lang
  try { localStorage.setItem(storageKey, lang) } catch { /* storage unavailable */ }
  applyDocumentLang(lang)
  for (const listener of listeners) listener()
}

function subscribe(listener: () => void) {
  listeners.add(listener)
  return () => { listeners.delete(listener) }
}

/** Re-renders the caller when the language changes. */
export function useLang(): Lang {
  return React.useSyncExternalStore(subscribe, getLang, getLang)
}

/** Locale for Intl date/number formatting; undefined keeps the browser default for English. */
export function intlLocale(): string | undefined {
  return intlLocales[current]
}

export function t(key: string, vars?: Record<string, string | number>): string {
  const template = current === 'en' ? key : dictionaries[current][key] ?? key
  if (!vars) return template
  return template.replace(/\{(\w+)\}/g, (match, name: string) => (name in vars ? String(vars[name]) : match))
}

/** Translates a snake_case server value (status, state, reason) when a translation exists. */
export function tState(value: string): string {
  if (!value) return t('Unknown')
  const human = value.replaceAll('_', ' ').replace(/\b\w/g, (letter) => letter.toUpperCase())
  return t(human)
}
