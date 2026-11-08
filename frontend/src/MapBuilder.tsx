import {useEffect, useMemo, useRef, useState} from 'react'
import type {Core} from 'cytoscape'
import {ArrowLeft, ArrowLeftRight, Check, Download, Focus, GitBranch, Layers3, Link2, Plus, Redo2, Save, Search, Trash2, Undo2, ZoomIn, ZoomOut} from 'lucide-react'
import BuilderCanvas, {nodeKinds, type BuilderLink, type BuilderNode, type NodeKind, type Selection, type SurfacePositions} from './BuilderCanvas'
import './mapBuilder.css'

type Content = {name: string; nodes: BuilderNode[]; links: BuilderLink[]}
type Summary = {id: number; name: string; revision: number; updated_at: string; source_key?: string | null; source_truncated?: boolean}
type SavedMap = Summary & Content
type Draft = {revision: number; content: Content}
type History = {past: Content[]; current: Content; future: Content[]}
type Editor = Selection | {kind: 'new-node'} | {kind: 'new-link'; source?: string}
const kinds = Object.keys(nodeKinds) as NodeKind[]
const relations = ['Resolves to', 'Hosts', 'Exposes', 'Contains route', 'Calls', 'Connects to', 'Depends on', 'Redirects to', 'Affects', 'Related to']
const requiredValues = ['domain', 'ip', 'network', 'origin', 'endpoint']
const maxNodes = 500
const maxLinks = 1000

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, {cache: 'no-store', ...init})
  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    const detail = body.detail
    const first = Array.isArray(detail) ? detail[0] : undefined
    const where = first?.loc?.[1] === 'nodes' && typeof first.loc[2] === 'number' ? 'Node ' + (first.loc[2] + 1) + ' · ' : ''
    throw new Error(typeof detail === 'string' ? detail : first ? where + first.msg.replace(/^Value error, /, '') : 'Request failed (' + response.status + ').')
  }
  return response.status === 204 ? undefined as T : response.json()
}

const json = (method: string, body: unknown) => ({method, headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)})
const initialHistory = (content: Content): History => ({past: [], current: content, future: []})
const contentOf = ({name, nodes, links}: SavedMap): Content => ({name, nodes, links})
const isSelection = (editor?: Editor): editor is Selection => editor?.kind === 'node' || editor?.kind === 'link'

function NodeEditor({node, onSave, onCancel}: {node?: BuilderNode; onSave: (value: Omit<BuilderNode, 'id' | 'x' | 'y'>) => void; onCancel: () => void}) {
  const [kind, setKind] = useState<NodeKind>(node?.kind ?? 'domain')
  const [label, setLabel] = useState(node?.label ?? '')
  const [value, setValue] = useState(node?.value ?? '')
  const [technology, setTechnology] = useState(node?.technology ?? '')
  const [version, setVersion] = useState(node?.version ?? '')
  const [os, setOs] = useState(node?.os ?? '')
  const [notes, setNotes] = useState(node?.notes ?? '')
  const identifier = requiredValues.includes(kind)
  const title = label.trim() || value.trim().slice(0, 160)
  return <form className="builder-editor" onSubmit={event => {
    event.preventDefault()
    if (title) onSave({kind, label: title, value: value.trim(), technology, version, os, notes})
  }}>
    <label>Asset type<select value={kind} onChange={event => setKind(event.target.value as NodeKind)}>
      {kinds.map(item => <option key={item} value={item}>{nodeKinds[item][0]}</option>)}
    </select></label>
    <label>{kind === 'service' || kind === 'filtered_port' ? 'Port / protocol' : kind === 'origin' || kind === 'endpoint' ? 'URL' : identifier ? 'Address' : 'Identifier'}
      <input type={kind === 'origin' || kind === 'endpoint' ? 'url' : 'text'} value={value} maxLength={1024} required={identifier}
        autoComplete="off" spellCheck={false} placeholder={nodeKinds[kind][2]} onChange={event => setValue(event.target.value)}/>
    </label>
    <label>Display name<input value={label} maxLength={160} placeholder={identifier ? 'Defaults to the address' : 'Name this asset'}
      onChange={event => setLabel(event.target.value)}/></label>
    {kind !== 'note' && <details className="builder-metadata" open={technology || version || os ? true : undefined}>
      <summary>Technology, version and OS</summary>
      <label>Technology<input value={technology} maxLength={160} placeholder="e.g. nginx" onChange={event => setTechnology(event.target.value)}/></label>
      <label>Version<input value={version} maxLength={100} placeholder="e.g. 1.27.5" onChange={event => setVersion(event.target.value)}/></label>
      <label>Operating system<input value={os} maxLength={160} placeholder="e.g. Ubuntu 24.04" onChange={event => setOs(event.target.value)}/></label>
    </details>}
    <label>Notes<textarea value={notes} maxLength={2000} rows={3} placeholder="Context or evidence to check" onChange={event => setNotes(event.target.value)}/></label>
    <div className="builder-actions">
      <button className="button primary" disabled={!title || (identifier && !value.trim())} type="submit"><Check size={14}/> {node ? 'Apply changes' : 'Add to map'}</button>
      <button type="button" className="button secondary" onClick={onCancel}>Cancel</button>
    </div>
  </form>
}

function LinkEditor({nodes, links, link, initialSource, onSave, onCancel}: {
  nodes: BuilderNode[]; links: BuilderLink[]; link?: BuilderLink; initialSource?: string;
  onSave: (value: Omit<BuilderLink, 'id'>) => void; onCancel: () => void
}) {
  const [source, setSource] = useState(link?.source ?? initialSource ?? '')
  const [target, setTarget] = useState(link?.target ?? '')
  const [relation, setRelation] = useState(link?.relation ?? 'Related to')
  const [notes, setNotes] = useState(link?.notes ?? '')
  const duplicate = links.some(item => item.id !== link?.id && item.source === source && item.target === target &&
    item.relation.toLowerCase() === relation.trim().toLowerCase())
  const enabled = source && target && source !== target && relation.trim() && !duplicate
  return <form className="builder-editor" onSubmit={event => {
    event.preventDefault()
    if (enabled) onSave({source, target, relation: relation.trim(), notes})
  }}>
    <label>From<select value={source} required onChange={event => setSource(event.target.value)}>
      <option value="">Choose source</option>{nodes.map(node => <option key={node.id} value={node.id}>{node.label} · {nodeKinds[node.kind][0]}</option>)}
    </select></label>
    <button className="button secondary compact builder-reverse" type="button" onClick={() => {setSource(target); setTarget(source)}}
      disabled={!source || !target}><ArrowLeftRight size={13}/> Reverse direction</button>
    <label>To<select value={target} required onChange={event => setTarget(event.target.value)}>
      <option value="">Choose destination</option>{nodes.map(node => <option key={node.id} value={node.id}>{node.label} · {nodeKinds[node.kind][0]}</option>)}
    </select></label>
    <label>Relationship<input required value={relation} maxLength={80} list="builder-relations" onChange={event => setRelation(event.target.value)}/></label>
    <datalist id="builder-relations">{relations.map(item => <option key={item} value={item}/>)}</datalist>
    <label>Notes<textarea value={notes} maxLength={2000} rows={3} placeholder="How are these assets connected?" onChange={event => setNotes(event.target.value)}/></label>
    {duplicate && <p className="builder-error" role="alert">This relationship already exists in that direction.</p>}
    {source && source === target && <p className="builder-error" role="alert">Choose two different assets.</p>}
    <div className="builder-actions">
      <button type="submit" className="button primary" disabled={!enabled}><Check size={14}/> {link ? 'Apply changes' : 'Add relationship'}</button>
      <button type="button" className="button secondary" onClick={onCancel}>Cancel</button>
    </div>
  </form>
}

function nextPosition(nodes: BuilderNode[]) {
  for (let index = 0; ; index++) {
    const x = (index % 3 - 1) * 200, y = Math.floor(index / 3) * 108
    if (!nodes.some(node => Math.abs(node.x - x) < 165 && Math.abs(node.y - y) < 66)) return {x, y}
  }
}

export default function MapBuilder({projectId, projectName, initialDraft, observedPositions, onBack, onObserve}: {
  projectId: number; projectName: string; initialDraft?: number;
  observedPositions?: SurfacePositions;
  onBack: (auditId?: number) => void; onObserve: (id: number, auditId?: number) => void
}) {
  const root = '/api/projects/' + projectId + '/surface-drafts'
  const storage = 'surfacemap.map-draft.' + projectId + '.'
  const graph = useRef<Core>(null)
  const inspector = useRef<HTMLElement>(null)
  const [maps, setMaps] = useState<Summary[]>([])
  const [opened, setOpened] = useState<SavedMap>()
  const [canvasVersion, setCanvasVersion] = useState(0)
  const [revision, setRevision] = useState(1)
  const [history, setHistory] = useState<History>()
  const [nameInput, setNameInput] = useState('')
  const [dirty, setDirty] = useState(false)
  const [busy, setBusy] = useState(true)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [search, setSearch] = useState('')
  const [showDiscoveredEndpoints, setShowDiscoveredEndpoints] = useState(true)
  const [editor, setEditor] = useState<Editor>()
  const [confirmation, setConfirmation] = useState<'delete' | 'reload'>()
  const content = history?.current
  const source = opened?.source_key
  const sourceAudit = source?.startsWith('audit:') ? Number(source.slice(6)) : undefined
  const canMatchLayout = opened?.id === initialDraft && content?.nodes.some(node => {
    const point = observedPositions?.[node.id]
    return point && (point.x !== node.x || point.y !== node.y)
  })
  const canvas = useMemo(() => {
    const nodes = content?.nodes ?? []
    const links = content?.links ?? []
    const endpoints = nodes.filter(item => item.kind === 'endpoint' && item.observed_asset_id)
    if (showDiscoveredEndpoints || !endpoints.length || endpoints.length === nodes.length) {
      return {nodes, links, endpointCount: endpoints.length}
    }
    const hidden = new Set(endpoints.map(item => item.id))
    return {nodes: nodes.filter(item => !hidden.has(item.id)),
      links: links.filter(item => !hidden.has(item.source) && !hidden.has(item.target)), endpointCount: endpoints.length}
  }, [content, showDiscoveredEndpoints])
  const selected = isSelection(editor) ? editor : undefined
  const node = editor?.kind === 'node' ? content?.nodes.find(item => item.id === editor.id) : undefined
  const link = editor?.kind === 'link' ? content?.links.find(item => item.id === editor.id) : undefined
  const linkSource = editor?.kind === 'new-link' ? editor.source : undefined
  const query = search.trim().toLowerCase()
  const visibleNodes = content?.nodes.filter(item =>
    [item.label, item.value, nodeKinds[item.kind][0]].some(value => value.toLowerCase().includes(query))) ?? []

  function remember(id: number, draft?: Draft) {
    try {
      if (draft) sessionStorage.setItem(storage + id, JSON.stringify(draft))
      else sessionStorage.removeItem(storage + id)
    } catch {
      if (draft) setNotice('Save this map before leaving. Temporary storage is unavailable.')
    }
  }

  function openDocument(map: SavedMap, restore = true) {
    let draft: Draft | undefined
    try {
      sessionStorage.setItem(storage + 'active', String(map.id))
      if (restore) draft = JSON.parse(sessionStorage.getItem(storage + map.id) ?? 'null') ?? undefined
    } catch { /* ignore unreadable drafts */ }
    if (!draft && map.revision === 1 && map.id === initialDraft && observedPositions &&
        map.nodes.length === Object.keys(observedPositions).length && map.nodes.every(node => observedPositions[node.id])) {
      map = {...map, nodes: map.nodes.map(node => ({...node, ...observedPositions[node.id]}))}
    }
    setOpened(map)
    setCanvasVersion(value => value + 1)
    setRevision(draft?.revision ?? map.revision)
    setHistory(initialHistory(draft?.content ?? contentOf(map)))
    setNameInput(draft?.content.name ?? map.name)
    setDirty(Boolean(draft))
    setNotice(draft ? 'Unsaved edits restored in this tab.' : '')
    setSearch('')
    setShowDiscoveredEndpoints(true)
    setEditor(undefined)
    setConfirmation(undefined)
  }

  useEffect(() => {
    const controller = new AbortController()
    const init = {signal: controller.signal}
    async function load() {
      try {
        const items = await request<Summary[]>(root, init)
        let active = 0
        try {active = Number(sessionStorage.getItem(storage + 'active'))} catch { /* use the latest map */ }
        const item = items.find(entry => entry.id === initialDraft) ?? items.find(entry => entry.id === active) ?? items[0]
        const map = item && await request<SavedMap>(root + '/' + item.id, init)
        if (controller.signal.aborted) return
        setMaps(items)
        if (map) openDocument(map)
      } catch (failure) {if (!controller.signal.aborted) setError((failure as Error).message)}
      finally {if (!controller.signal.aborted) setBusy(false)}
    }
    void load()
    return () => controller.abort()
  }, [root, storage, initialDraft, observedPositions])

  async function perform(action: () => Promise<void>) {
    setBusy(true); setError(''); setNotice('')
    try {await action()} catch (failure) {setError((failure as Error).message)}
    finally {setBusy(false)}
  }

  async function choose(id: number, restore = true) {
    await perform(async () => {
      const map = await request<SavedMap>(root + '/' + id)
      if (!restore) remember(id)
      openDocument(map, restore)
    })
  }

  async function create() {
    await perform(async () => {
      const used = new Set(maps.map(map => map.name))
      let name = 'Untitled map'
      for (let number = 2; used.has(name); number++) name = 'Untitled map ' + number
      const map = await request<SavedMap>(root, json('POST', {name}))
      setMaps(items => [map, ...items])
      openDocument(map)
    })
  }

  async function save() {
    const name = nameInput.trim()
    if (!opened || !content || busy || !name || (!dirty && name === content.name)) return
    await perform(async () => {
      const map = await request<SavedMap>(root + '/' + opened.id, json('PUT', {...content, name, revision}))
      remember(map.id)
      setOpened(map)
      setRevision(map.revision)
      setNameInput(map.name)
      setHistory(current => current && {...current, current: contentOf(map)})
      setMaps(items => [map, ...items.filter(item => item.id !== map.id)])
      setDirty(false)
      setNotice('Map saved.')
    })
  }

  async function removeMap() {
    if (!opened) return
    await perform(async () => {
      await request(root + '/' + opened.id + '?revision=' + revision, {method: 'DELETE'})
      remember(opened.id)
      const remaining = maps.filter(item => item.id !== opened.id)
      setMaps(remaining)
      setOpened(undefined); setHistory(undefined); setEditor(undefined); setDirty(false); setConfirmation(undefined)
      if (remaining[0]) openDocument(await request<SavedMap>(root + '/' + remaining[0].id))
    })
  }

  function updateHistory(next: History) {
    if (!opened || busy) return
    setHistory(next)
    setNameInput(next.current.name)
    const changed = JSON.stringify(next.current) !== JSON.stringify(contentOf(opened))
    setDirty(changed)
    setError(''); setNotice('')
    remember(opened.id, changed ? {revision, content: next.current} : undefined)
  }

  function commit(next: Content) {
    if (!history) return
    updateHistory({past: [...history.past.slice(-39), history.current], current: next, future: []})
  }

  function travel(direction: 'undo' | 'redo') {
    if (!history) return
    const {past, current, future} = history
    const next = direction === 'undo'
      ? past.length && {past: past.slice(0, -1), current: past[past.length - 1], future: [current, ...future]}
      : future.length && {past: [...past, current], current: future[0], future: future.slice(1)}
    if (next) {updateHistory(next); setEditor(undefined)}
  }

  function show(next?: Editor, focus = false) {
    setEditor(next)
    if (focus) inspector.current?.scrollIntoView({block: 'nearest'})
  }

  function applyNode(values: Omit<BuilderNode, 'id' | 'x' | 'y'>) {
    if (!content) return
    const item = node ? {...node, ...values} : {...values, id: crypto.randomUUID(), ...nextPosition(content.nodes)}
    commit({...content, nodes: node ? content.nodes.map(old => old.id === item.id ? item : old) : [...content.nodes, item]})
    show({kind: 'node', id: item.id})
    if (!node) requestAnimationFrame(() => {
      const cy = graph.current
      if (cy) cy.center(cy.getElementById(item.id))
    })
  }

  function applyLink(values: Omit<BuilderLink, 'id'>) {
    if (!content) return
    const item = {...values, id: link?.id ?? crypto.randomUUID()}
    commit({...content, links: link ? content.links.map(old => old.id === item.id ? item : old) : [...content.links, item]})
    show({kind: 'link', id: item.id})
  }

  function removeSelection() {
    if (!content || !selected) return
    if (selected.kind === 'node') commit({...content, nodes: content.nodes.filter(item => item.id !== selected.id),
      links: content.links.filter(item => item.source !== selected.id && item.target !== selected.id)})
    else commit({...content, links: content.links.filter(item => item.id !== selected.id)})
    show()
  }

  function move(id: string, x: number, y: number) {
    if (!content || !content.nodes.some(item => item.id === id && (item.x !== x || item.y !== y))) return
    commit({...content, nodes: content.nodes.map(item => item.id === id ? {...item, x, y} : item)})
  }

  function zoom(factor: number) {
    const cy = graph.current
    if (cy) cy.zoom({level: cy.zoom() * factor, renderedPosition: {x: cy.width() / 2, y: cy.height() / 2}})
  }

  function fit() {
    const cy = graph.current
    if (!cy?.nodes().length) return
    cy.fit(undefined, 44)
    if (cy.zoom() > 1) {cy.zoom(1); cy.center()}
  }

  function exportMap() {
    if (!content) return
    const blob = new Blob([JSON.stringify({format: 'surfacemap-builder', version: 1, ...content}, null, 2)], {type: 'application/json'})
    const url = URL.createObjectURL(blob)
    const download = document.createElement('a')
    download.href = url
    download.download = (content.name.toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-|-$/g, '') || 'attack-surface') + '.json'
    download.click()
    window.setTimeout(() => URL.revokeObjectURL(url), 1000)
  }

  return <section className={'workspace-page map-builder' + (source ? ' observed-draft' : '')} aria-busy={busy}>
    <header className="page-heading">
      <div><div className="eyebrow"><span className="live-pulse"/> ASSET INTELLIGENCE / {projectName}</div>
        <h1>Attack Surface Map</h1><p className="subtitle">Edit assets and relationships, arrange the map and save your changes.</p></div>
      <button className="button secondary" onClick={() => onBack(sourceAudit)}><ArrowLeft size={14}/> Observed map</button>
    </header>
    <div className="panel builder-bar">
      <label>Project maps<select value={opened?.id ?? ''} disabled={busy || !maps.length}
        onChange={event => void choose(Number(event.target.value))}>
        {!opened && <option value="">Select a map</option>}
        {maps.map(map => <option key={map.id} value={map.id}>{map.name}</option>)}
      </select></label>
      <button className="button secondary" disabled={busy} onClick={() => void create()}><Plus size={15}/> New map</button>
      {content && <>
        <label className="builder-name">Map name<input value={nameInput} maxLength={120} disabled={busy}
          onChange={event => setNameInput(event.target.value)}
          onKeyDown={event => {if (event.key === 'Enter') event.currentTarget.blur()}} onBlur={event => {
            const name = event.target.value.trim()
            if (name && name !== content.name) commit({...content, name})
            else setNameInput(content.name)
          }}/></label>
        <div className="builder-actions builder-save">
          <button className="button secondary" onClick={exportMap}><Download size={14}/> JSON</button>
          <button className="button primary" disabled={busy || (!dirty && (!nameInput.trim() || nameInput.trim() === content.name))}
            onClick={() => void save()}><Save size={14}/> Save map</button>
        </div>
      </>}
    </div>
    {error && <div className="form-error" role="alert">{error}</div>}
    {source && <div className="builder-source">
      <strong>{sourceAudit ? 'Based on audit #' + sourceAudit : 'Based on discovered project assets'}</strong>
      <span>Edits apply to this copy. Later scans appear in the observed map.</span>
      {opened?.source_truncated && <span>The observed map reached its display limit of 500 assets or 1,000 links.</span>}
    </div>}
    {content && <div className="builder-state">
      <span role="status">{notice || (dirty ? 'Unsaved edits · kept in this tab' : 'Saved to this project')}</span>
      <button className="text-action" disabled={busy} onClick={() => dirty ? setConfirmation('reload') : void choose(opened!.id, false)}>Reload saved</button>
      <button className="text-action builder-delete" disabled={busy} onClick={() => setConfirmation('delete')}>Delete map</button>
    </div>}
    {confirmation && opened && <div className="builder-confirm panel" role="alert">
      <span>{confirmation === 'delete' ? 'Delete this map and its saved assets and links?' : 'Discard unsaved edits and reload the saved map?'}</span>
      <div className="builder-actions">
        <button className="button secondary" disabled={busy} onClick={() => setConfirmation(undefined)}>Cancel</button>
        <button className={'button ' + (confirmation === 'delete' ? 'danger' : 'primary')} disabled={busy}
          onClick={() => void (confirmation === 'delete' ? removeMap() : choose(opened.id, false))}>
          {confirmation === 'delete' ? 'Delete this map' : 'Discard and reload'}
        </button>
      </div>
    </div>}
    {!content ? <div className="panel builder-empty">
      <Layers3 size={30}/><h2>{busy ? 'Loading maps…' : 'Start with a blank canvas'}</h2>
      <p>Start with a domain or IP, or open the observed map to edit discovered assets.</p>
      <button className="button primary" disabled={busy} onClick={() => void create()}><Plus size={15}/> Create map</button>
    </div> : <>
      <div className="panel builder-toolbar">
        <div className="builder-actions">
          <button className="button primary" disabled={busy || content.nodes.length >= maxNodes} onClick={() => show({kind: 'new-node'}, true)}><Plus size={15}/> Add asset</button>
          <button className="button secondary" disabled={busy || content.nodes.length < 2 || content.links.length >= maxLinks}
            onClick={() => show({kind: 'new-link', source: node?.id}, true)}><Link2 size={15}/> Add link</button>
          {canvas.endpointCount > 0 && canvas.endpointCount < content.nodes.length &&
            <button className="button secondary" aria-pressed={showDiscoveredEndpoints} onClick={() => {
              setShowDiscoveredEndpoints(value => !value)
              requestAnimationFrame(fit)
            }}>Discovered endpoints ({canvas.endpointCount})</button>}
        </div>
        <div className="builder-actions">
          <button className="button secondary" title="Undo" aria-label="Undo" disabled={busy || !history?.past.length} onClick={() => travel('undo')}><Undo2 size={15}/></button>
          <button className="button secondary" title="Redo" aria-label="Redo" disabled={busy || !history?.future.length} onClick={() => travel('redo')}><Redo2 size={15}/></button>
          <button className="button secondary" aria-label="Zoom out" disabled={!content.nodes.length} onClick={() => zoom(1 / 1.25)}><ZoomOut size={15}/></button>
          <button className="button secondary" aria-label="Zoom in" disabled={!content.nodes.length} onClick={() => zoom(1.25)}><ZoomIn size={15}/></button>
          <button className="button secondary" disabled={!content.nodes.length} onClick={fit}><Focus size={15}/> Fit map</button>
          {canMatchLayout && <button className="button secondary" disabled={busy} onClick={() => {
            commit({...content, nodes: content.nodes.map(node => observedPositions?.[node.id]
              ? {...node, ...observedPositions[node.id]} : node)})
            requestAnimationFrame(fit)
          }}>Use observed layout</button>}
        </div>
      </div>
      <div className="builder-workspace">
        <div className="panel builder-board">
          <div className="builder-board-head"><strong>Canvas</strong><span>
            {content.nodes.length} {content.nodes.length === 1 ? 'asset' : 'assets'} · {content.links.length} {content.links.length === 1 ? 'link' : 'links'}
          </span></div>
          <BuilderCanvas key={canvasVersion} graph={graph} nodes={canvas.nodes} links={canvas.links} selection={selected} onSelect={show} onMove={move} observed={Boolean(source)}/>
          {!content.nodes.length && <div className="builder-empty builder-overlay">
            <GitBranch size={28}/><h2>Your canvas is empty</h2><p>Add an asset to start mapping.</p>
            <button className="button primary" disabled={busy} onClick={() => show({kind: 'new-node'}, true)}><Plus size={14}/> Add first asset</button>
          </div>}
          <div className="builder-board-foot">Drag a node to move it. Drag the background to pan. Select a node or arrow to inspect it.</div>
        </div>
        <aside className="panel builder-inspector" ref={inspector} aria-label="Map inspector">
          <h2>{editor?.kind === 'new-node' ? 'Add asset' : editor?.kind === 'new-link' ? 'Add relationship' : node ? 'Asset details' : link ? 'Relationship details' : 'Inspector'}</h2>
          {node && <div className="builder-selection"><i style={{background: nodeKinds[node.kind][1]}}/>{nodeKinds[node.kind][0]}<strong>{node.label}</strong></div>}
          {link && <div className="builder-selection">{link.relation}<strong>
            {content.nodes.find(item => item.id === link.source)?.label} → {content.nodes.find(item => item.id === link.target)?.label}
          </strong></div>}
          <fieldset className="builder-fieldset" disabled={busy}>
            {(node || editor?.kind === 'new-node') && <NodeEditor key={node ? node.id + ':' + opened?.revision : 'new'} node={node} onSave={applyNode} onCancel={() => show()}/>}
            {(link || editor?.kind === 'new-link') && <LinkEditor key={link ? link.id + ':' + opened?.revision : 'new-link:' + linkSource} nodes={content.nodes}
              links={content.links} link={link} initialSource={linkSource} onSave={applyLink} onCancel={() => show()}/>}
            {selected && <div className="builder-actions builder-selection-actions">
              {node && content.nodes.length > 1 && content.links.length < maxLinks &&
                <button className="button secondary compact" onClick={() => show({kind: 'new-link', source: node.id})}><Link2 size={13}/> Connect from here</button>}
              {node?.observed_asset_id && <button className="button secondary compact"
                onClick={() => onObserve(node.observed_asset_id!, sourceAudit)}>Original evidence</button>}
              <button className="button secondary compact builder-delete" onClick={removeSelection}><Trash2 size={13}/> {node ? 'Remove asset' : 'Remove link'}</button>
            </div>}
          </fieldset>
          {!editor && <p>Select an asset or link to edit its details, or add a new one.</p>}
        </aside>
        <section className="panel builder-inventory" aria-label="Map inventory">
          <div className="builder-board-head"><strong>Inventory</strong><label><Search size={14}/>
            <input aria-label="Search map inventory" value={search} placeholder="Find an asset…" onChange={event => setSearch(event.target.value)}/>
          </label></div>
          <div className="builder-list">
            {visibleNodes.map(item => <button key={item.id} type="button" aria-pressed={node?.id === item.id} onClick={() => {
              show({kind: 'node', id: item.id}, true)
              if (item.kind === 'endpoint' && item.observed_asset_id) setShowDiscoveredEndpoints(true)
              requestAnimationFrame(() => {
                const cy = graph.current
                if (cy) {
                  if (cy.zoom() < .75) cy.zoom(.75)
                  cy.center(cy.getElementById(item.id))
                }
              })
            }}><i style={{background: nodeKinds[item.kind][1]}}/><span>{item.label}</span><small>{nodeKinds[item.kind][0]}</small></button>)}
            {!visibleNodes.length && <p>{query ? 'No matching assets.' : 'Assets you add appear here.'}</p>}
          </div>
          {content.links.length > 0 && <details className="builder-link-list"><summary>Relationships · {content.links.length}</summary>
            <div className="builder-list">{content.links.map(item => <button key={item.id} type="button" aria-pressed={link?.id === item.id}
              onClick={() => show({kind: 'link', id: item.id}, true)}>
              <Link2 size={14}/><span>{content.nodes.find(node => node.id === item.source)?.label} → {content.nodes.find(node => node.id === item.target)?.label}</span>
              <small>{item.relation}</small>
            </button>)}</div>
          </details>}
        </section>
      </div>
    </>}
  </section>
}
