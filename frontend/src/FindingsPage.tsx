import { useEffect, useState, type FormEvent } from 'react'
import { ArrowRight, FileText, ListFilter, Save, Search, ShieldCheck, Target, Terminal } from 'lucide-react'
import ScanConsole from './ScanLog'
import FindingVerification from './FindingVerification'

export type Finding = {
  id: number
  asset_id: number | null
  title: string
  severity: string
  template_id: string
  matched_at: string
  status: string
  first_seen: string
  last_seen: string
  evidence: Record<string, unknown>
  review: {notes?: string; remediation?: string; updated_at?: string}
}
const priorities = ['critical', 'high', 'medium', 'low', 'info', 'unknown']
const statuses = [
  ['open', 'Open'], ['confirmed', 'Confirmed'], ['accepted', 'Risk accepted'],
  ['resolved', 'Resolved'], ['false_positive', 'False positive'],
]
const statusName = (status: string) => statuses.find(item => item[0] === status)?.[1] ?? status
const rank = (severity: string) => priorities.includes(severity) ? priorities.indexOf(severity) : priorities.length

export default function FindingsPage({project, findings, search, initialFinding, auditId, onUpdate, onRetest, onReports, onClearAudit}: {
  project: {id: number; name: string}
  findings: Finding[]
  search: string
  initialFinding?: number
  auditId?: number
  onUpdate: (finding: Finding) => void
  onRetest: (finding: Finding) => void
  onReports: () => void
  onClearAudit: () => void
}) {
  const [selectedId, setSelectedId] = useState(initialFinding)
  const [severity, setSeverity] = useState('')
  const [status, setStatus] = useState('')
  const [query, setQuery] = useState(search)
  const visible = findings.filter(finding => (!severity || finding.severity === severity)
    && (!status || finding.status === status)
    && `${finding.title} ${finding.matched_at} ${finding.template_id}`.toLowerCase().includes(query.trim().toLowerCase()))
    .sort((a, b) => rank(a.severity) - rank(b.severity) || b.last_seen.localeCompare(a.last_seen))
  const selected = visible.find(finding => finding.id === selectedId) ?? visible[0]
  return <section className="workspace-page findings-page">
    <header className="page-heading"><div><div className="eyebrow"><span className="live-pulse"/> EVIDENCE / {project.name}</div>
      <h1>Finding review</h1><p className="subtitle">Inspect the matched target, record your assessment, and prepare targeted retests.</p>
    </div><button className="button secondary" onClick={onReports}><FileText size={15}/> Reports</button></header>
    {auditId && <div className="surface-scope-strip"><span>Findings observed in audit #{auditId}</span>
      <button className="text-action" onClick={onClearAudit}>All project findings</button></div>}
    <div className="audit-layout finding-layout">
      <section className="panel finding-queue">
        <div className="panel-head"><div><div className="panel-title"><ListFilter size={15}/> Findings</div>
          <div className="panel-sub">{visible.length} shown · {findings.length} recorded</div></div></div>
        <div className="audit-panel-body finding-filters">
          <label><Search size={14}/> Search<input value={query} onChange={event => setQuery(event.target.value)} placeholder="Title, URL or template ID"/></label>
          <div className="audit-form-row">
            <label>Severity<select value={severity} onChange={event => setSeverity(event.target.value)}>
              <option value="">All severities</option>{priorities.map(value => <option key={value}>{value}</option>)}
            </select></label>
            <label>Status<select value={status} onChange={event => setStatus(event.target.value)}>
              <option value="">All states</option>{statuses.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
            </select></label>
          </div>
        </div>
        <div className="finding-queue-items">
          {visible.map(finding => <button key={finding.id} className={`finding-queue-row ${selected?.id === finding.id ? 'selected' : ''}`}
            aria-pressed={selected?.id === finding.id} onClick={() => setSelectedId(finding.id)}>
            <span className={`severity severity-${finding.severity}`}>{finding.severity}</span>
            <span><b>{finding.title}</b><small>{finding.matched_at}</small></span>
            <small>{statusName(finding.status)}</small>
          </button>)}
          {!visible.length && <div className="data-empty">No findings match the selected filters.</div>}
        </div>
      </section>
      {selected ? <Review key={selected.id} projectId={project.id} finding={selected} onUpdate={onUpdate} onRetest={onRetest}/>
        : <section className="panel data-empty">Run an audit or import scanner evidence to review a finding.</section>}
    </div>
  </section>
}

type Retest = {id: number; status: string; tool_version: string | null; created_at: string;
  result: {outcome: string; reason: string; matchers?: string[]}}
const retestLabels: Record<string, string> = {
  reproduced: 'Reproduced', not_reproduced: 'Not reproduced', inconclusive: 'Inconclusive', pending: 'In progress',
}

function RetestHistory({projectId, findingId}: {projectId: number; findingId: number}) {
  const [rows, setRows] = useState<Retest[]>()
  const [error, setError] = useState('')
  const [openId, setOpenId] = useState<number>()
  const open = rows?.find(row => row.id === openId)
  useEffect(() => {
    const controller = new AbortController()
    let timer: number | undefined
    async function load() {
      try {
        const response = await fetch('/api/projects/' + projectId + '/findings/' + findingId + '/retests', {
          cache: 'no-store', signal: controller.signal,
        })
        if (!response.ok) throw new Error()
        const result: Retest[] = await response.json()
        if (controller.signal.aborted) return
        setRows(result)
        setError('')
        if (result.some(row => row.result.outcome === 'pending')) timer = window.setTimeout(load, 3000)
      } catch {
        if (!controller.signal.aborted) {
          setError('Could not load retest history. Reconnecting…')
          timer = window.setTimeout(load, 5000)
        }
      }
    }
    void load()
    return () => {controller.abort(); window.clearTimeout(timer)}
  }, [projectId, findingId])

  return <section className="retest-history" aria-label="Retest history">
    <h3>Retest history</h3>
    {error && <p role="status">{error}</p>}
    {rows?.length === 0 && <p>Run an exact retest to start the history for this finding.</p>}
    {rows?.map(row => <article className="retest-row" key={row.id}>
      <div><span className={'job-status job-' + (row.result.outcome === 'inconclusive' ? 'partial' : row.status)}>
        {retestLabels[row.result.outcome] ?? row.result.outcome}</span>
        <small>Scan #{row.id} · {new Date(row.created_at).toLocaleString()}{row.tool_version && ' · Nuclei ' + row.tool_version}</small>
      </div>
      <button className="button secondary compact" onClick={() => setOpenId(row.id)}><Terminal size={13}/> Console</button>
      {row.result.reason && <p>{row.result.reason}</p>}
      {!!row.result.matchers?.length && <p>Matched {row.result.matchers.join(', ')}</p>}
    </article>)}
    {open && <ScanConsole key={open.id} projectId={projectId} job={{id: open.id, status: open.status, label: 'Retest of finding #' + findingId}}
      onClose={() => setOpenId(undefined)}/>}
  </section>
}

function Review({projectId, finding, onUpdate, onRetest}: {
  projectId: number; finding: Finding; onUpdate: (finding: Finding) => void; onRetest: (finding: Finding) => void
}) {
  const [status, setStatus] = useState(finding.status)
  const [notes, setNotes] = useState(finding.review?.notes ?? '')
  const [remediation, setRemediation] = useState(finding.review?.remediation ?? '')
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const evidence = finding.evidence ?? {}
  const description = typeof evidence.description === 'string' ? evidence.description : ''
  const suggestedFix = typeof evidence.remediation === 'string' ? evidence.remediation : ''
  const references = Array.isArray(evidence.references) ? evidence.references.filter(
    (item): item is string => typeof item === 'string' && /^https?:\/\//i.test(item)
  ) : []
  const matchers = Array.isArray(evidence.observed_matchers)
    ? evidence.observed_matchers.filter((item): item is string => typeof item === 'string')
    : typeof evidence['matcher-name'] === 'string' ? [evidence['matcher-name']] : []
  const canRetest = /^https?:\/\//i.test(finding.matched_at) && /^[A-Za-z0-9_-]{1,160}$/.test(finding.template_id)

  async function save(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    setError('')
    setMessage('')
    try {
      const response = await fetch(`/api/projects/${projectId}/findings/${finding.id}`, {
        method: 'PATCH', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({status, notes, remediation}),
      })
      const payload = await response.json()
      if (!response.ok) throw new Error(typeof payload.detail === 'string' ? payload.detail : 'Could not save review')
      onUpdate(payload)
      setMessage('Review saved.')
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Could not save review')
    } finally {
      setBusy(false)
    }
  }

  return <section className="panel finding-review">
    <div className="panel-head"><div><div className="panel-title"><ShieldCheck size={15}/> Evidence and review</div>
      <div className="panel-sub">Finding #{finding.id} · {statusName(finding.status)}</div></div>
      {canRetest && <button className="button secondary compact" onClick={() => onRetest(finding)}><Target size={14}/> Prepare retest <ArrowRight size={13}/></button>}
    </div>
    <div className="audit-panel-body">
      <h2>{finding.title}</h2>
      <code className="audit-target">{finding.matched_at}</code>
      <div className="audit-run-summary"><span className={`severity severity-${finding.severity}`}>{finding.severity}</span>
        {finding.template_id && <code>{finding.template_id}</code>}<small>Last seen {new Date(finding.last_seen).toLocaleString()}</small></div>
      {description && <p className="finding-evidence-text">{description}</p>}
      {finding.template_id && <details className="finding-evidence"><summary>How to verify</summary>
        <FindingVerification templateId={finding.template_id} target={finding.matched_at} matchers={matchers}/>
      </details>}
      {suggestedFix && <p className="finding-evidence-text"><b>Template guidance</b><br/>{suggestedFix}</p>}
      {references.length > 0 && <ul className="audit-notes">{references.map(reference => <li key={reference}><a href={reference} target="_blank" rel="noreferrer">{reference}</a></li>)}</ul>}
      {!!matchers.length && <div className="finding-matchers"><b>Observed matchers</b><ul>{matchers.map(matcher => <li key={matcher}><code>{matcher}</code></li>)}</ul></div>}
      <details className="finding-evidence"><summary>Recorded evidence</summary><pre>{JSON.stringify(evidence, null, 2)}</pre></details>
      {canRetest && <RetestHistory projectId={projectId} findingId={finding.id}/>}
      <form className="finding-review-form" onSubmit={save}>
        <label>Review state<select value={status} onChange={event => setStatus(event.target.value)}>
          {statuses.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
        </select></label>
        <label>Analyst notes<textarea value={notes} maxLength={4000} rows={3} onChange={event => setNotes(event.target.value)}
          placeholder="Record reproduction, confidence, and affected behavior."/></label>
        <label>Remediation<textarea value={remediation} maxLength={4000} rows={3} onChange={event => setRemediation(event.target.value)}
          placeholder="Record the recommended fix or agreed follow-up."/></label>
        {error && <div role="alert" className="form-error">{error}</div>}
        {message && <p role="status" className="settings-saved">{message}</p>}
        <button className="button primary compact" disabled={busy}><Save size={14}/> Save review</button>
      </form>
    </div>
  </section>
}
