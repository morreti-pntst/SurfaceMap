import { lazy, Suspense, useEffect, useRef, useState } from 'react'
import type { Finding } from './FindingsPage'
import type { ScanSeed } from './ScanJobsPage'
import type { SurfacePositions } from './BuilderCanvas'
import ProjectsPage, {ProjectSwitcher, type Project} from './ProjectsPage'
import ProjectSearch from './ProjectSearch'
import { Activity, AlertTriangle, ArrowDownRight, ArrowUpRight, Box, CircleHelp, Command, Copy, Crosshair, Database, Download, FileUp, Fingerprint, Folder, Gauge, GitBranch, Globe2, Layers3, Plus, Power, Settings2, Shield, SlidersHorizontal, Target, Workflow } from 'lucide-react'
const AttackMap = lazy(() => import('./AttackMap'))
const MapBuilder = lazy(() => import('./MapBuilder'))
const ToolsPage = lazy(() => import('./ToolsPage'))
const ScanJobsPage = lazy(() => import('./ScanJobsPage'))
const ReportsPage = lazy(() => import('./ReportsPage'))
const SettingsPage = lazy(() => import('./SettingsPage'))
const WorkflowPage = lazy(() => import('./WorkflowPage'))
const AuditPage = lazy(() => import('./AuditPage'))
const FindingsPage = lazy(() => import('./FindingsPage'))

type Asset = { id: number; asset_type: string; canonical_value: string; first_seen: string; last_seen: string }
type ImportBatch = { id: number; format: string; filename: string; imported_at: string; records_seen: number; assets_created: number; findings_created: number; warnings: string[] }
type ImportPreview = { format: string; filename: string; records: number; assets: number; findings: number; warnings: string[] }
type TimelineEvent = { id: number; event_type: string; asset: string; source: string; observed_at: string; details: Record<string, unknown> }
type Snapshot = { id: number; captured_at: string; asset_count: number; relationship_count: number; finding_counts: Record<string, number> }
type Services = { database:string; redis:string; worker:string; active_jobs:number; active_tool_operations:number }
const nav = [
  { group: 'WORKSPACE', items: [['Overview', Gauge], ['Projects', Folder], ['Attack Surface Map', Layers3], ['Assets', Box], ['Findings', Shield], ['Timeline', Activity]] },
  { group: 'OPERATIONS', items: [['Audit', Target], ['Tool Center', Crosshair], ['Import Center', FileUp], ['Scan Jobs', Workflow], ['Workflow Builder', GitBranch], ['Reports', Fingerprint]] },
  { group: 'SYSTEM', items: [['Tool Manager', Settings2], ['Settings', SlidersHorizontal]] },
] as const
const disabled = new Set<string>()
const linked = new URLSearchParams(window.location.search)
const linkedRun = Number(linked.get('run')) || undefined
const linkedDraft = Number(linked.get('draft')) || undefined
const linkedEditor = linked.get('view') === 'builder' || linked.get('mode') === 'edit'
const linkedView = linkedEditor || linked.get('view') === 'map' ? 'Attack Surface Map' : linked.get('view') === 'audit' ? 'Audit' : 'Overview'

export default function App() {
  const [projects, setProjects] = useState<Project[]>([])
  const [selected, setSelected] = useState<Project | null>(null)
  const [view, setView] = useState(linkedView)
  const [nickname, setNickname] = useState(() => localStorage.getItem('surfacemap.nickname') ?? '')
  const initials = Array.from(nickname).slice(0, 2).join('').toUpperCase() || 'LO'
  const [version, setVersion] = useState('')
  const [initialScan, setInitialScan] = useState<ScanSeed>()
  const [mapFocus, setMapFocus] = useState<string>()
  const [mapAudit, setMapAudit] = useState<number | undefined>(linkedView === 'Attack Surface Map' ? linkedRun : undefined)
  const [editingMap, setEditingMap] = useState(linkedEditor)
  const [builderDraft, setBuilderDraft] = useState(linkedEditor ? linkedDraft : undefined)
  const [builderPositions, setBuilderPositions] = useState<SurfacePositions>()
  const [auditSelection, setAuditSelection] = useState<number | undefined>(linkedView === 'Audit' ? linkedRun : undefined)
  const [auditTarget, setAuditTarget] = useState<string>()
  const [findingFocus, setFindingFocus] = useState<number>()
  const [findingAudit, setFindingAudit] = useState<number>()
  const [findingQuery, setFindingQuery] = useState('')
  const [assetType, setAssetType] = useState('')

  const [searchText,setSearchText]=useState('')
  const [modal, setModal] = useState(false)
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [error, setError] = useState('')
  const [api, setApi] = useState<'checking'|'online'|'offline'>('checking')
  const [services,setServices]=useState<Services>({database:'checking',redis:'checking',worker:'checking',active_jobs:0,active_tool_operations:0})
  const [loading, setLoading] = useState(false)
  const [assets, setAssets] = useState<Asset[]>([])
  const [activeScans,setActiveScans]=useState(0)
  const [findings, setFindings] = useState<Finding[]>([])
  const [imports, setImports] = useState<ImportBatch[]>([])
  const [timeline, setTimeline] = useState<TimelineEvent[]>([])
  const [snapshots, setSnapshots] = useState<Snapshot[]>([])
  const [snapshotBusy, setSnapshotBusy] = useState(false)
  const [importFormat, setImportFormat] = useState('nmap_xml')
  const [importFile, setImportFile] = useState<File | null>(null)
  const [importPreview, setImportPreview] = useState<ImportPreview | null>(null)
  const [importResult, setImportResult] = useState<ImportBatch | null>(null)
  const [importError, setImportError] = useState('')
  const [importBusy, setImportBusy] = useState(false)
  const [dataError, setDataError] = useState('')
  const [scopeValue, setScopeValue] = useState('')
  const [scopeKind, setScopeKind] = useState('domain')
  const [scopeExcluded, setScopeExcluded] = useState(false)
  const [scopeError, setScopeError] = useState('')
  async function refresh() {
    try { const [health, response,system] = await Promise.all([fetch('/api/health'), fetch('/api/projects'),fetch('/api/system/status')]); if (!health.ok || !response.ok) throw new Error(); const rows: Project[] = await response.json(); if(system.ok)setServices(await system.json()); setVersion((await health.json()).version); setProjects(rows); setSelected(current => current ? rows.find(p => p.id === current.id) ?? rows[0] ?? null : rows.find(project => String(project.id) === (linked.get('project') ?? localStorage.getItem('surfacemap.project'))) ?? rows[0] ?? null); setApi('online') }
    catch { setApi('offline') }
  }
  useEffect(() => { void refresh() }, [])
  useEffect(() => {
    const timer = window.setInterval(() => {
      void fetch('/api/system/status', {cache: 'no-store'}).then(response => {
        if (response.ok) return response.json().then(setServices)
      }).catch(() => {})
    }, 10000)
    return () => window.clearInterval(timer)
  }, [])
  useEffect(() => {
    if (selected) localStorage.setItem('surfacemap.project', String(selected.id))
  }, [selected?.id])
  useEffect(() => { window.scrollTo(0, 0) }, [view, selected?.id])
  useEffect(() => {
    if (!selected) return
    const root = '/api/projects/' + selected.id
    const controller = new AbortController()
    setDataError('')
    async function load(path: string) {
      const response = await fetch(root + path, {signal: controller.signal})
      if (!response.ok) throw new Error('Could not load project data')
      return response.json()
    }
    const updates: Promise<unknown>[] = []
    if (['Overview', 'Assets', 'Findings'].includes(view)) {
      const auditFilter = view === 'Findings' && findingAudit ? '?audit_id=' + findingAudit : ''
      updates.push(load('/assets').then(setAssets), load('/findings' + auditFilter).then(setFindings))
    }
    if (view === 'Import Center') updates.push(load('/imports').then(setImports))
    if (['Timeline', 'Overview'].includes(view)) {
      updates.push(load('/timeline').then(setTimeline))
    }
    if (view === 'Timeline') updates.push(load('/snapshots').then(setSnapshots))
    void Promise.all(updates).catch(error => {
      if (!controller.signal.aborted) setDataError(error instanceof Error ? error.message : 'Could not load project data')
    })
    return () => controller.abort()
  }, [selected?.id, view, findingAudit])
  useEffect(()=>{
    if(!selected){setActiveScans(0);return}
    let live=true
    const load=()=>fetch(`/api/projects/${selected.id}/scan-jobs`).then(r=>r.ok?r.json():[]).then((jobs:{status:string}[])=>{if(live)setActiveScans(jobs.filter(job=>job.status==='queued'||job.status==='running').length)}).catch(()=>{if(live)setActiveScans(0)})
    void load();const timer=window.setInterval(()=>void load(),5000);return()=>{live=false;window.clearInterval(timer)}
  },[selected?.id])
  async function captureSnapshot() {
    if (!selected) return
    setSnapshotBusy(true); setDataError('')
    try { const response = await fetch(`/api/projects/${selected.id}/snapshots`, {method:'POST'}); const data = await response.json(); if (!response.ok) throw new Error(data.detail ?? 'Could not capture snapshot'); setSnapshots(current => [data, ...current]) }
    catch (e) { setDataError(e instanceof Error ? e.message : 'Could not capture snapshot') }
    finally { setSnapshotBusy(false) }
  }
  function prepareRetest(finding: Finding) {
    const source = finding.evidence.scan_target
    setInitialScan({target: typeof source === 'string' ? source : finding.matched_at, expectedMatch: finding.matched_at,
      templateId: finding.template_id, severity: finding.severity, retestFindingId: finding.id})
    setView('Scan Jobs')
  }
  function selectProject(project: Project | null) {
    if (project?.id === selected?.id) {choose('Overview'); return}
    setAssets([])
    setFindings([])
    setImports([])
    setTimeline([])
    setSnapshots([])
    setActiveScans(0)
    setSearchText('')
    setAssetType('')
    setImportFile(null)
    setImportPreview(null)
    setImportResult(null)
    setImportError('')
    setScopeError('')
    choose('Overview')
    setSelected(project)
  }
  function focusMap(assetId: number, auditId?: number) {
    setEditingMap(false)
    setMapAudit(auditId)
    setMapFocus(String(assetId))
    setView('Attack Surface Map')
  }
  function inspectAudit(auditId: number) {
    setEditingMap(false)
    setMapFocus(undefined)
    setMapAudit(auditId)
    setView('Attack Surface Map')
  }
  function editObservedMap(draftId?: number, auditId?: number, positions?: SurfacePositions) {
    setBuilderDraft(draftId)
    setBuilderPositions(positions)
    setMapAudit(auditId)
    setEditingMap(true)
    setView('Attack Surface Map')
  }
  function planAudit(target: string) {
    setAuditTarget(target)
    setAuditSelection(undefined)
    setView('Audit')
  }
  function prepareScan(seed: ScanSeed) {
    setInitialScan(seed)
    setView('Scan Jobs')
  }
  function saveProject(project: Project, open: boolean) {
    setProjects(current => [project, ...current.filter(item => item.id !== project.id)])
    if (open) selectProject(project)
    else if (selected?.id === project.id) setSelected(project)
  }
  function removeProject(id: number) {
    const remaining = projects.filter(project => project.id !== id)
    setProjects(remaining)
    if (selected?.id === id) selectProject(remaining[0] ?? null)
  }
  function focusFinding(findingId?: number, auditId?: number) {
    if (findingAudit !== auditId) setFindings([])
    setFindingAudit(auditId)
    setFindingQuery('')
    setFindingFocus(findingId)
    setView('Findings')
  }
  function updateFinding(finding: Finding) {
    setFindings(current => current.map(item => item.id === finding.id ? finding : item))
  }
  function exportCsv(filename: string, rows: Array<Array<string | number>>) {
    const cell = (value: string | number) => {
      let text = String(value)
      if (/^[\t\r\n]/.test(text) || /^[=+\-@]/.test(text.trimStart())) text = `'${text}`
      return `"${text.replaceAll('"', '""')}"`
    }
    const content = '\uFEFF' + rows.map(row => row.map(cell).join(',')).join('\r\n')
    const url = URL.createObjectURL(new Blob([content], {type:'text/csv;charset=utf-8'}))
    const link = document.createElement('a'); link.href = url; link.download = filename.replace(/[<>:"/\\|?*\u0000-\u001f]/g, '-') ; link.click()
    window.setTimeout(() => URL.revokeObjectURL(url), 1000)
  }
  async function createProject(e: React.FormEvent) {
    e.preventDefault(); setError(''); setLoading(true)
    try { const r = await fetch('/api/projects', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({name, description}) }); const data = await r.json(); if (!r.ok) throw new Error(data.detail ?? 'Could not create project'); setName(''); setDescription(''); setModal(false); saveProject(data, true) }
    catch (e) { setError(e instanceof Error ? e.message : 'Request failed') } finally { setLoading(false) }
  }
  async function addScope(e: React.FormEvent) {
    e.preventDefault(); setScopeError('')
    if (!selected) { setScopeError('Create or select a project first'); return }
    try {
      const r = await fetch(`/api/projects/${selected.id}/scope`, { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({value:scopeValue, kind:scopeKind, excluded:scopeExcluded}) })
      const data = await r.json()
      if (!r.ok) throw new Error(data.detail ?? 'Could not add scope entry')
      setScopeValue(''); await refresh()
    } catch (e) { setScopeError(e instanceof Error ? e.message : 'Request failed') }
  }
  const fullScope = selected?.scopes.some(entry => entry.kind === 'all' && !entry.excluded) ?? false
  async function toggleFullScope() {
    if (!selected) return
    setScopeError('')
    try {
      const response = await fetch(`/api/projects/${selected.id}/scope/full-access?enabled=${!fullScope}`, {method: 'PUT'})
      if (!response.ok) throw new Error((await response.json()).detail ?? 'Could not update scope')
      await refresh()
    } catch (e) {
      setScopeError(e instanceof Error ? e.message : 'Could not update scope')
    }
  }
  async function removeScope(scopeId:number) {
    if(!selected)return
    setScopeError('')
    try{const r=await fetch(`/api/projects/${selected.id}/scope/${scopeId}`,{method:'DELETE'});if(!r.ok)throw new Error((await r.json()).detail??'Could not remove scope entry');await refresh()}
    catch(e){setScopeError(e instanceof Error?e.message:'Could not remove scope entry')}
  }
  function makeImportForm() {
    const form = new FormData()
    form.set('file_format', importFormat)
    if (importFile) form.set('file', importFile)
    return form
  }
  async function previewFile(e: React.FormEvent) {
    e.preventDefault(); setImportError(''); setImportResult(null); setImportPreview(null)
    if (!selected || !importFile) { setImportError('Select a project and an output file'); return }
    setImportBusy(true)
    try { const r = await fetch(`/api/projects/${selected.id}/imports/preview`, {method:'POST', body:makeImportForm()}); const data=await r.json(); if(!r.ok) throw new Error(data.detail ?? 'Preview failed'); setImportPreview(data) }
    catch(e) { setImportError(e instanceof Error ? e.message : 'Preview failed') } finally { setImportBusy(false) }
  }
  async function commitImport() {
    if (!selected || !importFile) return
    setImportError(''); setImportBusy(true)
    try { const r=await fetch(`/api/projects/${selected.id}/imports`, {method:'POST', body:makeImportForm()}); const data=await r.json(); if(!r.ok) throw new Error(data.detail ?? 'Import failed'); setImportResult(data); setImportPreview(null); setImports(current=>[data,...current]); await refresh() }
    catch(e) { setImportError(e instanceof Error ? e.message : 'Import failed') } finally { setImportBusy(false) }
  }
  const choose = (label: string) => {
    if (disabled.has(label)) return
    setInitialScan(undefined)
    setMapFocus(undefined)
    setMapAudit(undefined)
    setEditingMap(false)
    setBuilderDraft(undefined)
    setBuilderPositions(undefined)
    setAuditTarget(undefined)
    setAuditSelection(undefined)
    setFindingFocus(undefined)
    if (findingAudit) setFindings([])
    setFindingAudit(undefined)
    setFindingQuery('')
    setView(label)
  }
  function searchInventory() {
    setAssetType('')
    setView('Assets')
  }
  const visibleAssets = assets.filter(asset => (!assetType || asset.asset_type === assetType)
    && [asset.asset_type, asset.canonical_value].join(' ').toLowerCase().includes(searchText.trim().toLowerCase()))
  const assetTypes = [...new Set(assets.map(asset => asset.asset_type))].sort()
  return <div className="shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark"><Crosshair size={22}/></div><div><strong>SURFACE<span>MAP</span></strong><small>ATTACK SURFACE INTELLIGENCE</small></div></div>
      <ProjectSwitcher projects={projects} selected={selected} onSelect={selectProject}
        onManage={() => choose('Projects')} onCreate={() => setModal(true)}/>
      <div className="nav-scroll">{nav.map(section => <section className="nav-section" key={section.group}><div className="nav-label">{section.group}</div>{section.items.map(([label, Icon]) => <button key={label} disabled={disabled.has(label)} title={disabled.has(label)?`${label} is not available in Foundation`:label} onClick={() => choose(label)} className={`nav-item ${view===label?'active':''} ${disabled.has(label)?'unavailable':''}`}><Icon size={16}/><span>{label}</span>{disabled.has(label) && <span className="soon-dot"/>}</button>)}</section>)}</div>
      <div className="sidebar-bottom"><div className="system-card"><div className="system-top"><span className={`status-dot ${api}`}/><span>API & database</span><b>{api==='online'?'Connected':api==='offline'?'Unavailable':'Checking'}</b></div><small>DB {services.database} · Redis {services.redis} · worker {services.worker}</small><small>{services.active_jobs} active scans · {services.active_tool_operations} tool operations</small></div><a className="help" href="/api/docs" target="_blank" rel="noreferrer"><CircleHelp size={15}/>API documentation</a><div className="user-row"><div className="avatar">{initials}</div><div><b>{nickname || 'Local operator'}</b><small>Single-user mode</small></div></div></div>
    </aside>
    <main className="main">
      <header className="topbar"><div className="crumb">Workspace <span>/</span> <b>{view}</b></div><div className="top-actions"><ProjectSearch projectId={selected?.id} value={searchText} onChange={setSearchText}
        onAsset={focusMap} onFinding={focusFinding} onInventory={searchInventory}/><a className="icon-btn" href="/api/docs" target="_blank" rel="noreferrer" title="Open API documentation"><CircleHelp size={17}/></a><FullStopHelp/><div className="avatar small-avatar" title={nickname || 'Local operator'}>{initials}</div></div></header>
      <div className="content">
      {view === 'Attack Surface Map' && editingMap && selected ? <Suspense fallback={<div className="data-empty">Loading map editor…</div>}>
        <MapBuilder key={selected.id} projectId={selected.id} projectName={selected.name} initialDraft={builderDraft}
          observedPositions={builderPositions} onObserve={focusMap}
          onBack={auditId => {setEditingMap(false); setMapFocus(undefined); setMapAudit(auditId)}}/>
      </Suspense> : view === 'Projects' ? <ProjectsPage projects={projects} selected={selected} onCreate={() => setModal(true)}
        onOpen={selectProject} onSave={saveProject} onDelete={removeProject}/> : view === 'Overview' ? <>
        <div className="page-heading"><div><div className="eyebrow"><span className="live-pulse"/> SECURITY OPERATIONS <span className="eyebrow-sep">/</span> LOCAL INSTANCE</div><h1>{view === 'Overview' ? 'Overview' : view}</h1><p className="subtitle">Your infrastructure at a glance. Stay ahead of what’s exposed.</p></div><div className="heading-actions"><button className="button secondary" onClick={()=>setModal(true)}><Plus size={16}/> New project</button><button className="button primary" onClick={()=>choose('Audit')} disabled={!selected}><Target size={15}/> Start an audit</button></div></div>
        <div className="status-banner"><div className="banner-icon"><Shield size={17}/></div><div><b>{api==='online'?'SurfaceMap is connected':'Connecting to local services'}</b><span>{api==='online'?'Project data, scoped scanner adapters, and tool lifecycle services are available locally.':'The API could not be reached. Start SurfaceMap with surfacemap start.'}</span></div><span className={`banner-state ${api}`}>{api==='online'?'API & DB ONLINE':'CHECK CONNECTION'}</span></div>
        <div className="metric-grid"><Metric icon={<Globe2/>} label="DISCOVERED ASSETS" value={api==='online'&&selected ? `${assets.length}` : '—'} note="Unique observed identities"/><Metric icon={<AlertTriangle/>} label="OPEN FINDINGS" value={api==='online'&&selected ? `${findings.filter(f=>f.status==='open').length}` : '—'} note="Imported and deduplicated"/><Metric icon={<Activity/>} label="ACTIVE SCANS" value={api==='online'&&selected?`${activeScans}`:'—'} note="Queued or running jobs"/><Metric icon={<Target/>} label="SCOPE ENTRIES" value={selected ? `${selected.scopes.length}` : '—'} note={selected ? 'Enforced before queued scans' : 'Select or create a project'} accent/></div>
        <div className="overview-grid"><section className="panel map-panel"><div className="panel-head"><div><div className="panel-title">Attack surface</div><div className="panel-sub">Infrastructure map <span className="coming">LIVE</span></div></div><button className="text-action" onClick={()=>choose('Attack Surface Map')} disabled={!selected}>Open map <ArrowUpRight size={14}/></button></div><div className="overview-evidence">
          <div><span>Domains</span><strong>{assets.filter(asset => asset.asset_type === 'domain').length}</strong></div>
          <div><span>IP addresses</span><strong>{assets.filter(asset => ['ipv4', 'ipv6'].includes(asset.asset_type)).length}</strong></div>
          <div><span>Web origins</span><strong>{assets.filter(asset => asset.asset_type === 'web_origin').length}</strong></div>
          <div><span>Web routes</span><strong>{assets.filter(asset => asset.asset_type === 'endpoint').length}</strong></div>
          <div><span>Open ports</span><strong>{assets.filter(asset => asset.asset_type === 'service').length}</strong></div>
          <div><span>Findings</span><strong>{findings.length}</strong></div>
        </div><div className="overview-evidence-footer"><button className="button secondary compact" disabled={!selected}
          onClick={() => choose('Assets')}><Box size={13}/> Browse inventory</button>
          <button className="button secondary compact" disabled={!selected} onClick={() => choose('Audit')}><Target size={13}/> Collect evidence</button>
        </div></section>
          <section className="panel activity-panel"><div className="panel-head"><div><div className="panel-title">Recent activity</div><div className="panel-sub">Latest changes across your workspace</div></div><button className="text-action" onClick={()=>setView('Timeline')}>View timeline <ArrowUpRight size={13}/></button></div><div className="activity-empty"><div className="empty-icon"><Activity size={19}/></div><b>{timeline.length?`${timeline.length} recent observations`:'No activity recorded yet'}</b><span>Imported and scan observations appear in the project timeline.</span></div><div className="activity-foot">Project history is available in Timeline.</div></section></div>
        <div className="lower-grid"><section className="panel projects-panel"><div className="panel-head"><div><div className="panel-title">Projects</div><div className="panel-sub">Your assessment workspaces</div></div><button className="text-action" onClick={()=>choose('Projects')}><Settings2 size={14}/> Manage projects</button></div>{projects.length ? <div className="project-list">{projects.map(p=><button className={`project-row ${selected?.id===p.id?'selected':''}`} key={p.id} onClick={()=>selectProject(p)}><div className="project-avatar">{p.name.slice(0,1).toUpperCase()}</div><div className="project-info"><b>{p.name}</b><small>{p.description || 'No description'} · {p.scopes.length} scope entries</small></div><span className="project-state"><i/> Stored</span><ArrowUpRight size={14}/></button>)}</div>:<div className="projects-empty"><div className="empty-icon"><Layers3 size={18}/></div><div><b>No projects created</b><span>Start with a project to define an authorized scope.</span></div><button className="button secondary compact" onClick={()=>setModal(true)}><Plus size={14}/> Create project</button></div>}<div className="scope-manager"><div className="scope-heading"><div><b>Authorized scope</b><span>{selected ? `Targets allowed or excluded for ${selected.name}` : 'Select or create a project to define authorized targets.'}</span></div><button type="button" className={`button ${fullScope ? 'primary' : 'secondary'} compact`} aria-pressed={fullScope} disabled={!selected || api !== 'online'} onClick={() => void toggleFullScope()}>{fullScope ? 'Disable full access' : 'Enable full access'}</button></div><form className="scope-form" onSubmit={addScope}><input aria-label="Scope value" value={scopeValue} onChange={e=>setScopeValue(e.target.value)} placeholder="example.com or 192.168.1.0/24" maxLength={253} required/><select aria-label="Scope type" value={scopeKind} onChange={e=>setScopeKind(e.target.value)}><option value="domain">Domain / wildcard</option><option value="ip">IP address</option><option value="cidr">CIDR network</option></select><label className="exclude-toggle"><input type="checkbox" checked={scopeExcluded} onChange={e=>setScopeExcluded(e.target.checked)}/> Exclude</label><button className="button secondary compact" disabled={!selected || api!=='online'}><Plus size={13}/> Add scope</button></form>{scopeError&&<div className="scope-error">{scopeError}</div>}<div className="scope-list">{selected?.scopes.length ? selected.scopes.map(entry=><div className="scope-entry" key={entry.id}><code>{entry.kind === 'all' ? 'All targets except exclusions' : entry.value}</code><span>{entry.kind === 'all' ? 'Full access' : entry.kind}</span><b className={entry.excluded?'excluded':'allowed'}>{entry.excluded?'Excluded':'Allowed'}</b><button type="button" className="scope-remove" aria-label={`Remove scope ${entry.value}`} title="Remove scope entry" onClick={()=>void removeScope(entry.id)}>×</button></div>) : <div className="scope-empty">{selected?'No scope entries added yet.':'Project scope will appear here.'}</div>}</div></div></section><section className="panel tools-panel"><div className="panel-head"><div><div className="panel-title">Tool inventory</div><div className="panel-sub">8 real, version-pinned adapters</div></div><button className="text-action" onClick={()=>setView('Tool Center')}>Open Tool Center <ArrowUpRight size={13}/></button></div><div className="tool-empty"><div className="tool-graphic"><Command size={20}/><span className="tool-cross">+</span></div><b>Tool Center and Tool Manager</b><span>Install tools, track versions, preview scoped commands, and inspect scan results.</span><button className="button secondary compact" onClick={()=>setView('Tool Manager')}><Settings2 size={14}/> Manage tools</button></div></section></div>
        </> : view === 'Audit' && selected ? <Suspense fallback={<div className="data-empty">Loading guided audit…</div>}><AuditPage key={[selected.id, auditTarget].join(':')} project={selected} initialTarget={auditTarget} initialRun={auditSelection} onNavigate={choose} onInspectAudit={inspectAudit} onReviewAudit={id=>focusFinding(undefined, id)} onInspectAsset={focusMap} onInspectFinding={focusFinding}/></Suspense> : view === 'Findings' && selected ? <Suspense fallback={<div className="data-empty">Loading finding review…</div>}><FindingsPage key={[selected.id, findingFocus, findingAudit, findingQuery].join(':')} project={selected} findings={findings} search={findingQuery} initialFinding={findingFocus} auditId={findingAudit} onClearAudit={()=>focusFinding()} onUpdate={updateFinding} onRetest={prepareRetest} onReports={()=>setView('Reports')}/></Suspense> : view === 'Attack Surface Map' && selected ? <Suspense fallback={<section className="workspace-page"><div className="data-empty">Loading graph tools…</div></section>}><AttackMap key={[selected.id, mapFocus, mapAudit].join(':')} projectId={selected.id} projectName={selected.name} initialFocus={mapFocus} initialAudit={mapAudit} onFinding={focusFinding} onAudit={planAudit} onScan={prepareScan} onBack={()=>setView('Overview')} onBuild={editObservedMap}/></Suspense> : view === 'Tool Center' || view === 'Tool Manager' ? <Suspense fallback={<section className="workspace-page"><div className="data-empty">Loading tool registry…</div></section>}><ToolsPage mode={view==='Tool Center'?'catalog':'manager'}/></Suspense> : view === 'Scan Jobs' && selected ? <Suspense fallback={<section className="workspace-page"><div className="data-empty">Loading scan jobs…</div></section>}><ScanJobsPage key={`${selected.id}:${initialScan?.templateId ?? ''}`} project={selected} initialScan={initialScan} onFinding={id=>focusFinding(id)}/></Suspense> : view === 'Workflow Builder' ? <Suspense fallback={<section className="workspace-page"><div className="data-empty">Loading workflow builder…</div></section>}><WorkflowPage project={selected}/></Suspense> : view === 'Reports' ? <Suspense fallback={<section className="workspace-page"><div className="data-empty">Loading reports…</div></section>}><ReportsPage project={selected}/></Suspense> : view === 'Settings' ? <Suspense fallback={<section className="workspace-page"><div className="data-empty">Loading settings…</div></section>}><SettingsPage nickname={nickname} onNickname={value => {localStorage.setItem('surfacemap.nickname', value); setNickname(value)}}/></Suspense> : <section className="workspace-page">
        <div className="page-heading"><div><div className="eyebrow"><span className="live-pulse"/> PROJECT DATA <span className="eyebrow-sep">/</span> {selected?.name ?? 'NO PROJECT SELECTED'}</div><h1>{view}</h1><p className="subtitle">{view === 'Import Center' ? 'Review and import existing scanner output into the project model.' : view === 'Assets' ? 'Normalized assets discovered through imported results.' : view === 'Timeline' ? 'Imported observations and saved inventory snapshots.' : 'Findings imported from supported scanner output.'}</p></div><button className="button secondary" onClick={()=>setView('Overview')}>Back to overview</button></div>
        {!selected && <div className="panel no-project"><b>Select or create a project first</b><span>Project data is isolated by workspace.</span><button className="button secondary compact" onClick={()=>setModal(true)}><Plus size={13}/> Create project</button></div>}
        {dataError && <div className="form-error">{dataError}</div>}
        {(view === 'Assets' || view === 'Findings') && selected && <div className="data-export"><span>Export this project’s {view.toLowerCase()} for offline review.</span><button className="button secondary compact" onClick={()=>view === 'Assets' ? exportCsv(`surfacemap-${selected.name}-assets.csv`, [['type','canonical_value','first_seen','last_seen'], ...assets.map(a=>[a.asset_type,a.canonical_value,a.first_seen,a.last_seen])]) : exportCsv(`surfacemap-${selected.name}-findings.csv`, [['severity','title','template_id','status','matched_at','first_seen','last_seen'], ...findings.map(f=>[f.severity,f.title,f.template_id,f.status,f.matched_at,f.first_seen,f.last_seen])])}><Download size={13}/> Export CSV</button></div>}
        {view === 'Timeline' && selected && <div className="timeline-layout"><section className="panel data-panel"><div className="panel-head"><div><div className="panel-title">Observation history</div><div className="panel-sub">Latest {timeline.length} imported observations</div></div></div>{timeline.length ? <div className="timeline-list">{timeline.map(event=><article className="timeline-event" key={event.id}><div className="timeline-marker"><Activity size={13}/></div><div className="timeline-event-copy"><b>{event.asset}</b><span>{event.event_type.replaceAll('_',' ')} · {event.source}</span></div><time>{new Date(event.observed_at).toLocaleString()}</time></article>)}</div> : <div className="data-empty">No imported observations yet.</div>}</section><section className="panel snapshots-panel"><div className="panel-head"><div><div className="panel-title">Inventory snapshots</div><div className="panel-sub">Capture asset and finding totals over time</div></div><button className="button secondary compact" disabled={snapshotBusy} onClick={()=>void captureSnapshot()}>{snapshotBusy?'Saving…':'Capture snapshot'}</button></div>{snapshots.length ? <div className="snapshot-list">{snapshots.map(snapshot=><article className="snapshot-row" key={snapshot.id}><b>{snapshot.asset_count} assets · {snapshot.relationship_count} links</b><span>{Object.entries(snapshot.finding_counts).map(([severity,count])=>`${severity} ${count}`).join(' · ') || 'No findings'}</span><time>{new Date(snapshot.captured_at).toLocaleString()}</time></article>)}</div> : <div className="data-empty">No snapshots captured yet.</div>}</section></div>}
        {view === 'Assets' && selected && <section className="panel data-panel"><div className="panel-head"><div><div className="panel-title">Assets</div><div className="panel-sub">{visibleAssets.length} shown · {assets.length} unique identities</div></div><select className="asset-type-filter" aria-label="Filter asset type" value={assetType} onChange={event=>setAssetType(event.target.value)}>
          <option value="">All asset types</option>{assetTypes.map(type => <option key={type} value={type}>{type.replaceAll('_', ' ')}</option>)}
        </select></div>{visibleAssets.length ? <div className="data-table"><div className="data-row table-header"><span>TYPE</span><span>CANONICAL VALUE</span><span>FIRST SEEN</span><span>LAST SEEN</span></div>{visibleAssets.map(a=><div className="data-row" key={a.id}><span className="asset-type">{a.asset_type}</span><button className="text-action asset-map-button" onClick={()=>focusMap(a.id)} title="Inspect on the map"><code>{a.canonical_value}</code><ArrowUpRight size={13}/></button><span>{new Date(a.first_seen).toLocaleString()}</span><span>{new Date(a.last_seen).toLocaleString()}</span></div>)}</div> : <div className="data-empty">{assets.length?'No assets match this search.':'No assets yet. Import scanner output to populate this list.'}</div>}</section>}
        {view === 'Import Center' && selected && <div className="import-layout"><section className="panel import-panel"><div className="panel-head"><div><div className="panel-title">Import scanner output</div><div className="panel-sub">Files are parsed locally and never executed · maximum size 10 MiB</div></div></div><form className="import-form" onSubmit={previewFile}><label>Format<select value={importFormat} onChange={e=>{setImportFormat(e.target.value);setImportPreview(null)}}><option value="nmap_xml">Nmap XML</option><option value="subfinder">Subfinder lines</option><option value="amass_jsonl">Amass JSONL</option><option value="amass_text">Amass text</option><option value="dnsx_jsonl">DNSx JSONL</option><option value="httpx_jsonl">httpx JSONL</option><option value="nuclei_jsonl">Nuclei JSONL</option><option value="katana_jsonl">Katana JSONL</option><option value="ffuf_json">FFUF JSON export</option><option value="ffuf_jsonl">FFUF JSONL stream</option><option value="generic_csv">Generic CSV (asset column)</option><option value="generic_json">Generic JSON (assets array)</option><option value="generic_xml">Generic XML (asset attributes)</option></select></label><label>Output file<input type="file" accept=".xml,.txt,.json,.jsonl,.csv" onChange={e=>{setImportFile(e.target.files?.[0] ?? null);setImportPreview(null);setImportResult(null)}} required/></label>{importFile&&<div className="selected-file"><FileUp size={15}/><span>{importFile.name}</span><small>{(importFile.size/1024).toFixed(1)} KiB</small></div>}{importError&&<div className="form-error">{importError}</div>}<div className="import-actions"><button className="button secondary" disabled={importBusy||!importFile}>{importBusy?'Working…':'Preview file'}</button>{importPreview&&<button type="button" className="button primary" disabled={importBusy||importPreview.records===0} onClick={()=>void commitImport()}>{importBusy?'Importing…':'Import records'}</button>}</div></form>{importPreview&&<div className="preview-summary"><b>Preview is ready</b><div><span>{importPreview.records} records</span><span>{importPreview.assets} unique assets</span><span>{importPreview.findings} findings</span></div>{importPreview.warnings.length>0&&<details><summary>{importPreview.warnings.length} parser warnings</summary><ul>{importPreview.warnings.slice(0,20).map((w,i)=><li key={i}>{w}</li>)}</ul></details>}</div>}{importResult&&<div className="import-success"><b>Import completed</b><span>{importResult.records_seen} records · {importResult.assets_created} new assets · {importResult.findings_created} new findings</span></div>}</section>
          <section className="panel history-panel"><div className="panel-head"><div><div className="panel-title">Import history</div><div className="panel-sub">Recorded source provenance</div></div></div>{imports.length ? <div className="history-list">{imports.map(item=><div className="history-row" key={item.id}><div><b>{item.filename}</b><span>{item.format} · {new Date(item.imported_at).toLocaleString()}</span></div><small>{item.records_seen} records</small></div>)}</div> : <div className="data-empty">No imports recorded.</div>}</section></div>}
      </section>}
        <footer className="footer"><span>SURFACEMAP <b>{version || "LOCAL"}</b> <i/> LOCAL INSTANCE</span><span>LOCAL-FIRST SECURITY OPERATIONS <span className="footer-sep">·</span> API {api==='online'?'CONNECTED':'UNAVAILABLE'}</span></footer>
      </div>
    </main>
    {modal && <div className="modal-backdrop" onMouseDown={e=>{if(e.target===e.currentTarget)setModal(false)}}><form className="modal" onSubmit={createProject}><div className="modal-kicker">WORKSPACE SETUP</div><h2>Create project</h2><p>Projects organize assets and define the authorized testing boundary.</p><label>Project name<input autoFocus value={name} onChange={e=>setName(e.target.value)} placeholder="e.g. Acme external assessment" required maxLength={120}/></label><label>Description <span className="optional">OPTIONAL</span><textarea value={description} onChange={e=>setDescription(e.target.value)} placeholder="Purpose, owner, or engagement context" rows={3} maxLength={2000}/></label>{error&&<div className="form-error">{error}</div>}<div className="modal-actions"><button type="button" className="button secondary" onClick={()=>setModal(false)}>Cancel</button><button className="button primary" disabled={loading||api!=='online'}>{loading?'Creating…':'Create project'}</button></div></form></div>}
  </div>
}

function FullStopHelp() {
  const dialog = useRef<HTMLDialogElement>(null)
  const [copyMessage, setCopyMessage] = useState('')
  async function copyStopCommand() {
    try {
      await navigator.clipboard.writeText('surfacemap stop')
      setCopyMessage('Stop command copied.')
    } catch {
      setCopyMessage('Select the command and copy it manually.')
    }
  }
  return <>
    <button type="button" className="button secondary full-stop-trigger" onClick={() => {
      setCopyMessage('')
      dialog.current?.showModal()
    }}><Power size={15}/> Full stop</button>
    <dialog ref={dialog} className="modal project-dialog full-stop-dialog" aria-labelledby="full-stop-title">
      <h2 id="full-stop-title">Fully stop SurfaceMap</h2>
      <p>Run this command in a terminal to stop scans and services and release the dashboard port. Projects and saved results stay on disk.</p>
      <div className="full-stop-command">
        <div><code>surfacemap stop</code><button type="button" className="button secondary compact" onClick={() => void copyStopCommand()} aria-label="Copy stop command"><Copy size={13}/> Copy</button></div>
        <span>On Windows, you can also double-click <code>stop.cmd</code> in the SurfaceMap folder.</span>
      </div>
      <div className="modal-actions full-stop-actions">
        <span role="status">{copyMessage}</span>
        <form method="dialog"><button type="submit" className="button secondary" autoFocus>Close</button></form>
      </div>
    </dialog>
  </>
}

function Metric({icon,label,value,note,accent=false}:{icon:React.ReactNode,label:string,value:string,note:string,accent?:boolean}) { return <div className="metric"><div className="metric-top"><div className={`metric-icon ${accent?'accent':''}`}>{icon}</div><span className="metric-tag">{accent?'PROJECT':'LIVE DATA'}</span></div><div className="metric-value">{value}</div><div className="metric-label">{label}</div><div className="metric-note">{note}</div></div> }
