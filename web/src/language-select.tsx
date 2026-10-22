import { languages, setLang, t, useLang, type Lang } from './i18n'

export function LanguageSelect() {
  const lang = useLang()
  return (
    <label className="lang-select" title={t('Language')}>
      <span className="material-symbols-rounded" aria-hidden="true">translate</span>
      <select aria-label={t('Language')} value={lang} onChange={(event) => setLang(event.target.value as Lang)}>
        {languages.map((item) => <option key={item.code} value={item.code}>{item.label}</option>)}
      </select>
    </label>
  )
}
