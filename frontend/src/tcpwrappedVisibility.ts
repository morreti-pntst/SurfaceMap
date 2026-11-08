import {useState} from 'react'

export function isTcpwrapped(value: unknown) {
  return typeof value === 'string' && /\btcpwrapped\b/i.test(value)
}

export function readTcpwrappedVisibility(projectId: number) {
  try {return localStorage.getItem('surfacemap.hide-tcpwrapped.' + projectId) === 'true'} catch {return false}
}

export function useTcpwrappedVisibility(projectId: number) {
  const key = 'surfacemap.hide-tcpwrapped.' + projectId
  const [hidden, setHidden] = useState(() => readTcpwrappedVisibility(projectId))
  function toggle() {
    const next = !hidden
    setHidden(next)
    try {
      if (next) localStorage.setItem(key, 'true')
      else localStorage.removeItem(key)
    } catch { /* The filter still works for this view. */ }
  }
  return {hidden, toggle}
}
