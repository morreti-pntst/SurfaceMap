import { useEffect, useMemo, useState } from 'react'
import { Activity, ArrowDownToLine, ArrowUpCircle, BookOpen, CheckCircle2, CircleAlert, Clock3, RefreshCw, RotateCcw, Search, Trash2, Wrench } from 'lucide-react'

type ToolProgress = { id:number; action:string; status:string; version:string; progress:string; error:string }
const operationPending = (op?: ToolProgress) => op?.status === "queued" || op?.status === "running"
const progressLabel = (op: ToolProgress) => op.status === "failed"
  ? op.error || "Open installation history for details."
  : op.progress || (op.status === "queued" ? "Waiting for an installation slot." : "Starting installer…")

type Tool = { id:string; name:string; category:string; description:string; binary:string; version:string|null; latest_version:string; status:string; source:string; documentation:string; license:{name:string;url:string}; installation_method:string; capabilities:string[]; active_adapter:boolean; operation?:ToolProgress; parameters:Array<Record<string,unknown>> }
type Operation = { id:number; tool_id:string; action:string; status:string; version:string; log:string; error:string; created_at:string; completed_at:string|null }

export default function ToolsPage({ mode }: { mode:'catalog'|'manager' }) {
  const [tools,setTools]=useState<Tool[]>([]),[operations,setOperations]=useState<Operation[]>([])
  const [query,setQuery]=useState(''),[category,setCategory]=useState('all'),[busy,setBusy]=useState(false),[error,setError]=useState('')
  const refresh=async()=>{const [tr,or]=await Promise.all([fetch('/api/tools'),fetch('/api/tool-operations')]);if(!tr.ok||!or.ok)throw new Error('Tool service is unavailable');setTools(await tr.json());setOperations(await or.json())}
  useEffect(()=>{void refresh().catch(e=>setError(e.message));const id=window.setInterval(()=>void refresh().catch(()=>{}),4000);return()=>window.clearInterval(id)},[])
  const categories=useMemo(()=>['all',...new Set(tools.map(tool=>tool.category))],[tools])
  const visible=tools.filter(tool=>(category==='all'||tool.category===category)&&`${tool.name} ${tool.description} ${tool.category}`.toLowerCase().includes(query.toLowerCase()))
  async function operate(toolId:string,action:string){setBusy(true);setError('');try{const response=await fetch(`/api/tools/${toolId}/operations`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action})});const body=await response.json();if(!response.ok)throw new Error(typeof body.detail==='string'?body.detail:'Operation could not be queued');await refresh()}catch(e){setError(e instanceof Error?e.message:'Tool operation failed')}finally{setBusy(false)}}
  async function installAll(){setBusy(true);setError('');try{const response=await fetch('/api/tools/operations/install-all',{method:'POST'});const body=await response.json();if(!response.ok)throw new Error(body.detail??'Could not queue installs');await refresh()}catch(e){setError(e instanceof Error?e.message:'Tool installation failed')}finally{setBusy(false)}}
  const recovered = operations.filter(op => op.status === 'failed' && operations.some(later =>
    later.id > op.id && later.tool_id === op.tool_id && later.version === op.version
    && later.status === 'completed' && ['install', 'update', 'reinstall'].includes(later.action)
    && ['install', 'update', 'reinstall'].includes(op.action)
  ))
  const recoveredIds = new Set(recovered.map(op => op.id))
  const currentHistory = operations.filter(op => !recoveredIds.has(op.id))
  function operationRow(op: Operation, wasRecovered = false) {
    const status = wasRecovered ? 'completed' : op.status
    const label = wasRecovered ? 'Recovered' : op.status === 'failed' ? 'Attempt failed' : op.status
    return (
      <details className="operation-row" key={op.id}>
        <summary>
          <b>{tools.find(tool => tool.id === op.tool_id)?.name ?? op.tool_id}</b>
          <span>{op.action} {op.version}</span>
          <i className={`tool-status status-${status}`}>{label}</i>
          <time>{new Date(op.created_at).toLocaleString()}</time>
        </summary>
        {wasRecovered && <div className="panel-sub">This attempt failed. A later operation verified the same version.</div>}
        {op.error && <div className="form-error">{op.error}</div>}
        {op.log && <pre>{op.log}</pre>}
      </details>
    )
  }

  return <section className="workspace-page tools-page">
    <div className="page-heading"><div><div className="eyebrow"><span className="live-pulse"/> OPERATIONS <span className="eyebrow-sep">/</span> {mode==='catalog'?'INTEGRATION CATALOG':'TOOL LIFECYCLE'}</div><h1>{mode==='catalog'?'Tool Center':'Tool Manager'}</h1><p className="subtitle">{mode==='catalog'?'Eight pinned, real command-line adapters with bounded defaults and project scope enforcement.':'Install and manage trusted tools in the persistent local Docker volume.'}</p></div>{mode==='catalog'&&<button className="button primary" disabled={busy} onClick={()=>void installAll()}><ArrowDownToLine size={14}/> Install or update all adapters</button>}</div>
    {error&&<div className="form-error">{error}</div>}
    {mode==='catalog'&&<div className="tools-toolbar"><label className="map-search"><Search size={14}/><input value={query} onChange={e=>setQuery(e.target.value)} placeholder="Search by tool or purpose…" aria-label="Search tools"/></label><select aria-label="Filter tools by category" value={category} onChange={e=>setCategory(e.target.value)}>{categories.map(item=><option value={item} key={item}>{item==='all'?'All categories':item}</option>)}</select><span className="map-count">{visible.length} adapters</span></div>}
    {mode==='catalog'?<div className="tool-grid">{visible.map(tool=>{const op=tool.operation;const pending=operationPending(op);return <article className="panel tool-card" key={tool.id}><div className="tool-card-top"><div className="tool-card-icon"><Wrench size={17}/></div><span className={`tool-status status-${tool.status.replaceAll('_','-')}`}>{tool.status.replaceAll('_',' ')}</span></div><div className="tool-category">{tool.category}</div><h2>{tool.name}</h2><p>{tool.description}</p><div className="tool-versions"><span>Installed <b>{tool.version??'Not installed'}</b></span><span>Latest pinned <b>{tool.latest_version}</b></span></div><div className="tool-license"><a href={tool.license.url} target="_blank" rel="noreferrer">{tool.license.name} license</a><small>{tool.installation_method}</small></div>{op&&<div className="tool-operation-line"><Clock3 size={12}/><span>{op.action} {op.version} · {op.status} · #{op.id}<br/>{progressLabel(op)}</span></div>}<div className="tool-card-actions"><a href={tool.documentation} target="_blank" rel="noreferrer"><BookOpen size={13}/> Docs</a>{pending?<button disabled><RefreshCw size={13}/> {op?.status==='queued'?'Queued':'In progress'}</button>:tool.status==='not_installed'||tool.status==='failed'?<button onClick={()=>void operate(tool.id,'install')} disabled={busy}><ArrowDownToLine size={13}/> Install</button>:tool.status==='update_available'||tool.status==='newer_than_pinned'?<button onClick={()=>void operate(tool.id,'update')} disabled={busy}><ArrowUpCircle size={13}/> Use pinned</button>:<button disabled title="Adapter is installed and passed its version check"><CheckCircle2 size={13}/> Ready</button>}</div></article>})}</div>:<div className="panel manager-panel"><div className="panel-head"><div><div className="panel-title">Installed tool versions</div><div className="panel-sub">Versioned installs are staged and activated only after the health check passes.</div></div><button className="button secondary compact" onClick={()=>void refresh()}><RefreshCw size={13}/> Refresh status</button></div><div className="data-table"><div className="tool-manager-row tool-manager-heading"><span>TOOL</span><span>INSTALLED</span><span>LATEST PINNED</span><span>STATUS</span><span>ACTIONS</span></div>{tools.map(tool=><div className="tool-manager-row" key={tool.id}><span><b>{tool.name}</b><small>{tool.category}</small></span><code>{tool.version??'—'}</code><code>{tool.latest_version}</code><span className={`tool-status status-${tool.status.replaceAll('_','-')}`}>{operationPending(tool.operation)?tool.operation?.status:tool.status.replaceAll('_',' ')}{tool.operation&&<small title={progressLabel(tool.operation)}>{progressLabel(tool.operation)}</small>}</span><div className="manager-actions"><button title="Update" onClick={()=>void operate(tool.id,tool.version?'update':'install')} disabled={busy||operationPending(tool.operation)}><ArrowUpCircle size={14}/></button><button title="Rollback" onClick={()=>void operate(tool.id,'rollback')} disabled={busy||operationPending(tool.operation)||!tool.version}><RotateCcw size={14}/></button><button title="Uninstall" onClick={()=>void operate(tool.id,'uninstall')} disabled={busy||operationPending(tool.operation)||tool.id==='nmap'||!tool.version}><Trash2 size={14}/></button><a href={tool.documentation} target="_blank" rel="noreferrer" title="Official documentation"><BookOpen size={14}/></a></div></div>)}</div></div>}
    <details className="panel tool-operation-panel">
      <summary className="panel-head">
        <div>
          <div className="panel-title"><Activity size={14}/> Installation history</div>
          <div className="panel-sub">Past attempts and their logs. Current availability is shown above.</div>
        </div>
      </summary>
      {currentHistory.length ? currentHistory.map(op => operationRow(op))
        : <div className="data-empty"><CircleAlert size={14}/> No tool operations recorded.</div>}
      {recovered.length > 0 && <details className="operation-row">
        <summary><b>Recovered attempts ({recovered.length})</b></summary>
        {recovered.map(op => operationRow(op, true))}
      </details>}
    </details>
  </section>
}
