import { useEffect, useRef, useState } from 'react'
import { Box, Search, Shield, X } from 'lucide-react'

type Hit = {id: number; label: string; detail: string}
type Results = {assets: Hit[]; findings: Hit[]}

export default function ProjectSearch({projectId, value, onChange, onAsset, onFinding, onInventory}: {
  projectId?: number; value: string; onChange: (value: string) => void
  onAsset: (id: number) => void; onFinding: (id: number) => void; onInventory: () => void
}) {
  const input = useRef<HTMLInputElement>(null)
  const root = useRef<HTMLDivElement>(null)
  const [open, setOpen] = useState(false)
  const [results, setResults] = useState<Results>()
  const [error, setError] = useState('')
  const query = value.trim()
  const hasMenu = open && Boolean(projectId) && query.length >= 2
  useEffect(() => {
    function shortcut(event: KeyboardEvent) {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        input.current?.focus()
      }
    }
    function outside(event: PointerEvent) {
      if (!root.current?.contains(event.target as Node)) setOpen(false)
    }
    document.addEventListener('keydown', shortcut)
    document.addEventListener('pointerdown', outside)
    return () => {
      document.removeEventListener('keydown', shortcut)
      document.removeEventListener('pointerdown', outside)
    }
  }, [])
  useEffect(() => {
    setResults(undefined)
    setError('')
    if (!hasMenu) return
    const controller = new AbortController()
    const timer = window.setTimeout(async () => {
      try {
        const response = await fetch('/api/projects/' + projectId + '/search?q=' + encodeURIComponent(query), {
          signal: controller.signal,
        })
        if (!response.ok) throw new Error()
        const payload = await response.json()
        if (!controller.signal.aborted) setResults(payload)
      } catch { if (!controller.signal.aborted) setError('Project search is temporarily unavailable.') }
    }, 200)
    return () => { controller.abort(); window.clearTimeout(timer) }
  }, [projectId, query, hasMenu])

  function choose(callback: (id: number) => void, id: number) {
    setOpen(false)
    onChange('')
    callback(id)
  }

  return <div className="project-search" ref={root} onKeyDown={event => {
    if (event.key === 'Escape') { setOpen(false); input.current?.focus() }
  }}>
    <form className="search global-search" role="search" onSubmit={event => {
      event.preventDefault()
      if (!query) return
      setOpen(false)
      input.current?.blur()
      onInventory()
    }}>
      <Search size={15}/>
      <input ref={input} aria-label="Search project assets and findings" aria-expanded={hasMenu}
        value={value} onFocus={() => setOpen(true)} onChange={event => {onChange(event.target.value); setOpen(true)}}
        maxLength={160} autoComplete="off" placeholder="Search assets or findings…"/>
      {value ? <button type="button" className="search-clear" aria-label="Clear search" onClick={() => {
        onChange(''); input.current?.focus()
      }}><X size={13}/></button> : <kbd>Ctrl K</kbd>}
    </form>
    {hasMenu && <div className="search-popover">
      {error && <small role="status">{error}</small>}
      {!results && !error && <small role="status">Searching the project…</small>}
      {results && (['assets', 'findings'] as const).map(group => results[group].length > 0 && <div key={group}>
        <div className="popover-caption">{group.toUpperCase()}</div>
        {results[group].map(item => <button key={item.id} onClick={() => choose(group === 'assets' ? onAsset : onFinding, item.id)}>
          {group === 'assets' ? <Box size={14}/> : <Shield size={14}/>}
          <span>{item.label}<small>{item.detail.replaceAll('_', ' ')}</small></span>
        </button>)}
      </div>)}
      {results && !results.assets.length && !results.findings.length && <small>No matching assets or findings.</small>}
      <button className="search-inventory" onClick={() => {setOpen(false); onInventory()}}>Open inventory for “{query}”</button>
    </div>}
  </div>
}
