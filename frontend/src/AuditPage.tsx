import { useEffect, useRef, useState, type FormEvent } from 'react'
import { AlertTriangle, ArrowRight, CheckCircle2, Clock3, Download, GitCompareArrows, Layers3, ListChecks, Play, Save, ShieldCheck, Square, Target, Terminal } from 'lucide-react'
import ScanConsole, {LiveScanProgress, type ConsoleJob} from './ScanLog'
import AuditComparison from './AuditComparison'

type Project = { id: number; name: string }
type Profile = 'full' | 'web' | 'domain' | 'passive'
type HttpEvidence = {
  status: number; url: string; redirect: string | null
  address?: string
  source?: 'preflight'
  posture: { headers_present: Record<string, boolean>; cors_wildcard: boolean; cors_credentials: boolean; cookies: Record<string, number> }
}
type Execution = { target: string; status: string; job_id?: number; records?: number; reason?: string; http?: HttpEvidence
  started_at?: string; completed_at?: string; diagnostic?: {category: string; http_status: number | null} }
type Stage = {
  id: string
  tool_id: string
  title: string
  source: string
  target_limit: number
  redirect_limit?: number
  ready: boolean
  status: string
  reason?: string
  excluded_or_over_limit?: number
  executions: Execution[]
}
type ScopeRule = { kind: string; value: string; excluded: boolean }
type ManualCheck = {id: string; title: string; description: string}
type ManualReview = {status: string; notes: string; updated_at?: string}
type Plan = { target: string; profile: Profile; stages: Stage[]; scope_snapshot: ScopeRule[]; max_jobs: number; notes: string[]; plan_token: string; config: {timeout_seconds: number} }
type AuditRun = Pick<Plan, 'target' | 'profile' | 'stages' | 'scope_snapshot'> & {
  id: number; status: string; error: string; created_at: string; completed_at: string | null
  config: {manual_checks?: ManualCheck[]; request?: Draft}; manual_review: Record<string, ManualReview>
}
type Wordlist = { name: string; path: string }
type Draft = {
  target: string
  user_agent: string
  profile: Profile
  root_domain: string
  expand_subdomains: boolean
  additional_hosts: number
  include_amass: boolean
  include_ports: boolean
  ports: string
  nmap_timeout_minutes: number | ''
  nuclei_mode: 'baseline' | 'focused' | 'broad' | 'off'
  wordlist: string
  rate: number
}
const initial: Draft = {
  target: '', user_agent: '', profile: 'full', root_domain: '', expand_subdomains: false, additional_hosts: 3,
  include_amass: false, include_ports: false, ports: '', nmap_timeout_minutes: 10,
  nuclei_mode: 'baseline', wordlist: '', rate: 2,
}
const profiles = [
  { id: 'full', title: 'Full surface audit', subtitle: 'All 8 scanners · domain, services and web routes' },
  { id: 'web', title: 'Web application', subtitle: 'One URL · HTTP, crawl and templates' },
  { id: 'domain', title: 'Domain + web', subtitle: 'Discovery, DNS and scoped web checks' },
  { id: 'passive', title: 'Passive discovery', subtitle: 'Domain evidence from public sources' },
] as const
const sources: Record<string, string> = {
  root_domain: 'Selected root domain',
  dns_hosts: 'Root, seed and allowed discovered hosts',
  web_candidates: 'Seed URL and allowed discovered hosts',
  seed_host: 'Seed host only',
  verified_web: 'Web targets with a confirmed HTTP response',
  verified_seed: 'Seed URL after a confirmed HTTP response',
}
const active = (status: string) => ['queued', 'running', 'cancelling'].includes(status)
const statusLabel = (status: string) => status.replaceAll('_', ' ')

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, {cache: 'no-store', ...init})
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}))
    const detail = payload.detail
    const message = typeof detail === 'string' ? detail
      : Array.isArray(detail) ? detail.map(item => item.msg).join('. ') : detail?.reason ?? detail?.message
    throw new Error(message || `Request failed (${response.status})`)
  }
  return response.json()
}

function HttpObservation({http}: {http: HttpEvidence}) {
  const {headers_present, cookies, cors_wildcard, cors_credentials} = http.posture
  const observed = Object.entries(headers_present).filter(([, present]) => present).map(([key]) => key)
  const absent = Object.entries(headers_present).filter(([, present]) => !present).map(([key]) => key)
  return <details className="http-observation">
    <summary>{http.source === 'preflight' ? 'Independent HTTP response' : 'Initial HTTP response'} · {http.status}{http.address && ' via ' + http.address} · headers and cookies</summary>
    <dl><dt>Headers present</dt><dd>{observed.join(', ') || 'None of the selected headers'}</dd>
      <dt>Headers absent</dt><dd>{absent.join(', ') || 'All selected headers present'}</dd>
      <dt>Cookies</dt><dd>{cookies.observed} observed · {cookies.secure} Secure · {cookies.httponly} HttpOnly · {cookies.samesite} SameSite</dd>
      <dt>CORS</dt><dd>Wildcard origin {cors_wildcard ? 'present' : 'absent'} · credentials {cors_credentials ? 'allowed by header' : 'absent'}</dd>
    </dl>
    <small>These observations describe one response. Review whether each header or flag applies to the endpoint.</small>
  </details>
}

function CheckReview({check, saved, url, onSave}: {check: ManualCheck; saved?: ManualReview; url: string; onSave: (run: AuditRun) => void}) {
  const [status, setStatus] = useState(saved?.status ?? 'pending')
  const [notes, setNotes] = useState(saved?.notes ?? '')
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  async function save(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    setError('')
    setMessage('')
    try {
      onSave(await request<AuditRun>(url, {
        method: 'PATCH', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({status, notes}),
      }))
      setMessage('Review saved.')
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Could not save coverage')
    } finally {
      setBusy(false)
    }
  }
  return <details className="finding-evidence manual-check">
    <summary>{check.title} · {statusLabel(saved?.status ?? 'pending')}</summary>
    <form onSubmit={save} className="finding-review-form">
      <small>{check.description}</small>
      <label>Coverage state<select value={status} onChange={event => setStatus(event.target.value)}>
        <option value="pending">Pending review</option><option value="reviewed">Reviewed</option>
        <option value="gap">Coverage gap</option><option value="not_applicable">Not applicable</option>
      </select></label>
      <label>Evidence and limitations<textarea value={notes} maxLength={4000} rows={3} onChange={event => setNotes(event.target.value)}/></label>
      {error && <p className="form-error" role="alert">{error}</p>}
      {message && <small role="status">{message}</small>}
      <button type="submit" className="button primary compact" disabled={busy}><Save size={14}/> Save coverage</button>
    </form>
  </details>
}

export default function AuditPage({project, initialTarget, initialRun, onNavigate, onInspectAudit, onReviewAudit, onInspectAsset, onInspectFinding}: {
  project: Project; initialTarget?: string; initialRun?: number; onNavigate: (view: string) => void
  onInspectAudit: (id: number) => void; onReviewAudit: (id: number) => void
  onInspectAsset: (asset: number, audit: number) => void; onInspectFinding: (finding: number, audit: number) => void
}) {
  const root = `/api/projects/${project.id}/audits`
  const [draft, setDraft] = useState({...initial, target: initialTarget ?? ''})
  const configuration = useRef<HTMLElement>(null)
  const [plan, setPlan] = useState<Plan>()
  const [acknowledged, setAcknowledged] = useState(false)
  const [runs, setRuns] = useState<AuditRun[]>([])
  const [selectedId, setSelectedId] = useState(initialRun)
  const [selectedJob, setSelectedJob] = useState<number>()
  const [comparing, setComparing] = useState(false)
  const [wordlists, setWordlists] = useState<Wordlist[]>([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [connectionError, setConnectionError] = useState('')
  const run = runs.find(item => item.id === selectedId)
  const full = draft.profile === 'full'
  const baselines = runs.filter(item => item.id !== run?.id && !active(item.status))
  const consoleJobs: ConsoleJob[] = run?.stages.flatMap(stage => stage.executions.flatMap(execution => execution.job_id ?
    [{id: execution.job_id, status: execution.status, label: stage.tool_id + ' · ' + execution.target}] : [])) ?? []
  const currentJob = consoleJobs.find(job => active(job.status))
  const openConsole = consoleJobs.find(job => job.id === selectedJob)
  const needsGentlerRun = run?.stages.some(stage => stage.executions.some(item =>
    ['rate_limit', 'connection', 'upstream'].includes(item.diagnostic?.category ?? '')))
  const nmapLimit = Number(run?.config.request?.nmap_timeout_minutes || 5)
  const needsLongerNmap = nmapLimit < 60 && run?.stages.some(stage => stage.tool_id === 'nmap' &&
    stage.executions.some(item => item.reason?.startsWith('Nmap reached')))

  function prepareRun(run: AuditRun, gentle = false, longerNmap = false) {
    const settings = {...initial, profile: run.profile, target: run.target, nmap_timeout_minutes: 5 as number,
      ...run.config.request}
    setDraft({...settings, ...(gentle ? {rate: 1, nuclei_mode: 'baseline' as const} : {}),
      ...(longerNmap ? {nmap_timeout_minutes: Math.min(60, nmapLimit * 2)} : {})})
    setPlan(undefined)
    setAcknowledged(false)
    setError('')
    configuration.current?.scrollIntoView({behavior: 'smooth', block: 'start'})
  }

  useEffect(() => {
    const controller = new AbortController()
    let timer: number | undefined
    async function refresh() {
      try {
        const recent = await request<AuditRun[]>(root, {signal: controller.signal})
        setRuns(recent)
        setConnectionError('')
        setSelectedId(current => recent.some(item => item.id === current) ? current : recent[0]?.id)
      } catch {
        if (!controller.signal.aborted) setConnectionError('Could not refresh audit history. Reconnecting…')
      } finally {
        if (!controller.signal.aborted) timer = window.setTimeout(refresh, 3000)
      }
    }
    void refresh()
    void request<Wordlist[]>('/api/wordlists', {signal: controller.signal}).then(setWordlists).catch(() => {})
    return () => {
      controller.abort()
      window.clearTimeout(timer)
    }
  }, [root])

  function change<K extends keyof Draft>(key: K, value: Draft[K]) {
    setDraft(previous => ({...previous, [key]: value,
      ...(key === 'profile' && value === 'full' && previous.nuclei_mode === 'off' ? {nuclei_mode: 'baseline' as const} : {})}))
    setPlan(undefined)
    setAcknowledged(false)
    setError('')
  }

  async function preview(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    setError('')
    setAcknowledged(false)
    try {
      setPlan(await request<Plan>(`${root}/preview`, {
        method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(draft),
      }))
    } catch (error) {
      setPlan(undefined)
      setError(error instanceof Error ? error.message : 'Plan could not be prepared')
    } finally {
      setBusy(false)
    }
  }

  async function start() {
    if (!plan || !acknowledged) return
    setBusy(true)
    setError('')
    try {
      const created = await request<AuditRun>(root, {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({...draft, confirm_scope: true, plan_token: plan.plan_token}),
      })
      setRuns(previous => [created, ...previous.filter(item => item.id !== created.id)])
      setSelectedId(created.id)
      setSelectedJob(undefined)
      setPlan(undefined)
      setAcknowledged(false)
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Audit could not start')
    } finally {
      setBusy(false)
    }
  }

  async function cancel(id: number) {
    setBusy(true)
    setError('')
    try {
      const updated = await request<AuditRun>(`${root}/${id}/cancel`, {method: 'POST'})
      setRuns(previous => previous.map(item => item.id === id ? updated : item))
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Audit could not be stopped')
    } finally {
      setBusy(false)
    }
  }

  const completed = run?.stages.filter(stage => stage.status === 'completed').length ?? 0
  const reviewedStages = run?.stages.filter(stage => !['pending', 'running'].includes(stage.status)).length ?? 0
  const executionCount = run?.stages.reduce((count, stage) => count + stage.executions.filter(item => item.job_id).length, 0) ?? 0

  return <section className="workspace-page audit-page">
    <header className="page-heading">
      <div><div className="eyebrow"><span className="live-pulse"/> OPERATIONS / {project.name}</div>
        <h1>Guided audit</h1>
        <p className="subtitle">Plan a scoped assessment, follow evidence across tools, and record coverage for handoff.</p>
      </div>
      <button className="button secondary" onClick={() => onNavigate('Overview')}><ShieldCheck size={15}/> Manage scope</button>
    </header>
    {error && <div className="form-error" role="alert"><AlertTriangle size={15}/> {error}</div>}
    {connectionError && <div className="form-error" role="status">{connectionError}</div>}
    <div className="audit-layout">
      <section className="panel audit-config" ref={configuration}>
        <div className="panel-head"><div><div className="panel-title"><Target size={15}/> Configure an audit</div>
          <div className="panel-sub">Choose what to verify. The plan makes no requests to the target.</div></div></div>
        <form onSubmit={preview}>
          <fieldset disabled={busy}>
            <legend>Coverage profile</legend>
            <div className="audit-profiles">
              {profiles.map(profile => <label key={profile.id} className={draft.profile === profile.id ? 'selected' : ''}>
                <input type="radio" name="profile" checked={draft.profile === profile.id} onChange={() => change('profile', profile.id)}/>
                <span><b>{profile.title}</b><small>{profile.subtitle}</small></span>
              </label>)}
            </div>
            <label>Seed URL or hostname
              <input value={draft.target} placeholder="https://app.example.com/" maxLength={1024} required
                onChange={event => change('target', event.target.value)}/>
              <small>Enter http:// explicitly for a plain HTTP target.</small>
            </label>
            {draft.profile !== 'web' && <>
              <label>Root domain <small>Optional. Defaults to the seed hostname.</small>
                <input value={draft.root_domain} placeholder="example.com" maxLength={253}
                  onChange={event => change('root_domain', event.target.value)}/>
              </label>
              {!full && <label className="audit-check"><input type="checkbox" checked={draft.include_amass}
                onChange={event => change('include_amass', event.target.checked)}/> Include Amass as a second discovery source</label>}
            </>}
            {(full || draft.profile === 'domain') && <>
              {!full && <label className="audit-check"><input type="checkbox" checked={draft.expand_subdomains}
                onChange={event => change('expand_subdomains', event.target.checked)}/> Follow discovered hosts already allowed by scope</label>}
              {(full || draft.expand_subdomains) && <label>Additional host limit
                <input type="number" min={1} max={5} required value={draft.additional_hosts}
                  onChange={event => change('additional_hosts', Number(event.target.value))}/>
                {full && <small>Only discovered hosts allowed by project scope are eligible. All discoveries can appear on the map.</small>}
              </label>}
            </>}
            {draft.profile !== 'passive' && <>
              <div className="audit-form-row">
                <label>Vulnerability templates
                  <select value={draft.nuclei_mode} onChange={event => change('nuclei_mode', event.target.value as Draft['nuclei_mode'])}>
                    <option value="baseline">Baseline · four common checks</option>
                    <option value="focused">Focused exposures and misconfigurations</option>
                    <option value="broad">Broad HTTP templates</option>
                    {!full && <option value="off">Skip Nuclei</option>}
                  </select>
                </label>
                <label>Requests / sec
                  <input type="number" min={1} max={5} required value={draft.rate}
                    onChange={event => change('rate', Number(event.target.value))}/>
                </label>
              </div>
              <label>User-Agent (optional)
                <input value={draft.user_agent} maxLength={512} placeholder="Tool default"
                  onChange={event => change('user_agent', event.target.value)}/>
              </label>
              {!full && <label className="audit-check"><input type="checkbox" checked={draft.include_ports}
                onChange={event => change('include_ports', event.target.checked)}/> Run Nmap service detection on the seed host</label>}
              {(full || draft.include_ports) && <label>Custom TCP ports <small>Optional. Leave blank for Nmap’s default 1,000 TCP ports.</small>
                <input value={draft.ports} maxLength={256} placeholder="e.g. 22,443,8000-8100"
                  onChange={event => change('ports', event.target.value)}/>
              </label>}
              {(full || draft.include_ports) && <label>Nmap time limit per target (minutes)
                <input type="number" min={1} max={60} required value={draft.nmap_timeout_minutes}
                  onChange={event => change('nmap_timeout_minutes', event.target.value === '' ? '' : Number(event.target.value))}/>
              </label>}
              <label>FFUF wordlist <small>Manage custom wordlists in Scan Jobs.</small>
                <select value={draft.wordlist} onChange={event => change('wordlist', event.target.value)}>
                  <option value="">{full ? 'Built-in · 12 common public paths' : 'Skip content discovery'}</option>
                  {wordlists.map(wordlist => <option key={wordlist.path} value={wordlist.path}>{wordlist.name}</option>)}
                </select>
              </label>
            </>}
            <button className="button primary" type="submit" disabled={!draft.target.trim()}><ListChecks size={15}/> Preview audit plan</button>
          </fieldset>
        </form>
      </section>

      <div className="audit-right">
        {plan && <section className="panel audit-plan">
          <div className="panel-head"><div><div className="panel-title"><ShieldCheck size={15}/> Plan ready for review</div>
            <div className="panel-sub">{plan.stages.length} stages · up to {plan.max_jobs} scan jobs · {Math.floor(plan.config.timeout_seconds / 60)}-minute total budget</div></div></div>
          <div className="audit-panel-body">
            <code className="audit-target">{plan.target}</code>
            <ol className="audit-stage-list">{plan.stages.map(stage => <li key={stage.id}>
              <b>{stage.title}</b><small>{sources[stage.source]} · up to {stage.target_limit} targets
                {!!stage.redirect_limit && ` · up to ${stage.redirect_limit} redirect probes per target`}</small>
              {!stage.ready && <span className="job-status job-failed">Adapter unavailable</span>}
            </li>)}</ol>
            <ul className="audit-notes">{plan.notes.map(note => <li key={note}>{note}</li>)}</ul>
            <details className="audit-scope"><summary>Review project scope ({plan.scope_snapshot.length})</summary>
              {plan.scope_snapshot.map((rule, i) => <p key={i}><code>{rule.value}</code> · {rule.excluded ? 'Excluded' : 'Allowed'}</p>)}
            </details>
            <label className="audit-check"><input type="checkbox" checked={acknowledged}
              onChange={event => setAcknowledged(event.target.checked)}/> I am authorized to run these checks against the selected scope.</label>
            <button className="button primary" disabled={!acknowledged || busy || !plan.stages.some(stage => stage.ready)} onClick={() => void start()}>
              <Play size={14}/> Start audit
            </button>
          </div>
        </section>}

        <section className="panel audit-run">
          <div className="panel-head"><div><div className="panel-title"><Clock3 size={15}/> Audit activity</div>
            <div className="panel-sub">Recorded checks, coverage gaps and artifacts</div></div>
            {run && active(run.status) && <button className="button danger compact" disabled={busy || run.status === 'cancelling'}
              onClick={() => void cancel(run.id)}><Square size={13}/> Stop audit</button>}
          </div>
          {runs.length > 0 && <div className="audit-panel-body audit-history">
            <label>Run <select aria-label="Audit run" value={selectedId ?? ''} onChange={event => {
              setSelectedId(Number(event.target.value))
              setSelectedJob(undefined)
              setComparing(false)
            }}>{runs.map(item => <option key={item.id} value={item.id}>#{item.id} · {item.target} · {statusLabel(item.status)}</option>)}</select></label>
          </div>}
          {run ? <div className="audit-panel-body">
            <div className="audit-run-summary"><span className={`job-status job-${run.status}`}>{statusLabel(run.status)}</span>
              <span>{reviewedStages} / {run.stages.length} stages processed · {completed} fully covered · {executionCount} scan jobs</span></div>
            {run.error && <p className="audit-run-note">{run.error}</p>}
            {currentJob && <LiveScanProgress key={currentJob.id} projectId={project.id} job={currentJob}
              onOpen={() => setSelectedJob(currentJob.id)}/>}
            {needsGentlerRun && <div className="audit-advice">
              <strong>Review connectivity before retrying</strong>
              <p>Wait for the service to recover or honor its Retry-After window. A baseline at 1 req/s reduces traffic. Use an owner-approved test window if broader coverage is required.</p>
              <button className="button secondary compact" onClick={() => prepareRun(run, true)}>Prepare low-rate baseline</button>
              <a href="https://docs.projectdiscovery.io/tools/nuclei/running" target="_blank" rel="noreferrer">Nuclei rate controls</a>
            </div>}
            {needsLongerNmap && <div className="audit-advice">
              <strong>Nmap reached its time limit</strong>
              <button className="button secondary compact" onClick={() => prepareRun(run, false, true)}>Prepare audit with more Nmap time</button>
            </div>}
            <ol className="audit-stage-list">{run.stages.map(stage => <li key={stage.id}>
              <div className="audit-stage-heading"><b>{stage.title}</b><span className={`job-status job-${stage.status}`}>{statusLabel(stage.status)}</span></div>
              {stage.reason && <small>{stage.reason}</small>}
              {!!stage.excluded_or_over_limit && <small>{stage.excluded_or_over_limit} discovered candidates outside scope or above the cap</small>}
              {stage.executions.map(execution => <div className="audit-execution" key={execution.target}>
                <div><code>{execution.target}</code><small>{statusLabel(execution.status)}{execution.records !== undefined ? ` · ${execution.records} records` : ''}</small></div>
                {execution.job_id && <button className="button secondary compact" onClick={() => setSelectedJob(execution.job_id)}>
                  <Terminal size={13}/> Console #{execution.job_id}
                </button>}
                {execution.reason && <p>{execution.reason}</p>}
                {execution.http && <HttpObservation http={execution.http}/>}
              </div>)}
            </li>)}</ol>
            <div className="audit-run-actions">
              <a className="button secondary compact" href={`${root}/${run.id}/report/html`}><Download size={14}/> HTML coverage report</a>
              <a className="button secondary compact" href={`${root}/${run.id}/report/json`}><Download size={14}/> JSON</a>
              <button className="button secondary compact" onClick={() => onReviewAudit(run.id)}>Review run findings <ArrowRight size={13}/></button>
              <button className="button secondary compact" onClick={() => onInspectAudit(run.id)}><Layers3 size={14}/> Map this audit</button>
              <button className="button secondary compact" onClick={() => prepareRun(run)}>Use run settings</button>
              {!active(run.status) && baselines.length > 0 && <button className="button secondary compact" onClick={() => setComparing(true)}>
                <GitCompareArrows size={14}/> Compare runs
              </button>}
            </div>
          </div> : <div className="data-empty"><CheckCircle2 size={15}/> Preview a plan to start the first audit in this project.</div>}
        </section>
        {run && !!run.config.manual_checks?.length && <section className="panel">
          <div className="panel-head"><div><div className="panel-title"><ListChecks size={15}/> Manual coverage</div>
            <div className="panel-sub">Record operator checks and gaps for the audit report.</div></div></div>
          <div className="audit-panel-body">{run.config.manual_checks.map(check => <CheckReview key={run.id + ':' + check.id}
            check={check} saved={run.manual_review[check.id]} url={root + '/' + run.id + '/review/' + check.id}
            onSave={updated => setRuns(previous => previous.map(item => item.id === updated.id ? updated : item))}/>)}</div>
        </section>}
      </div>
    </div>
    {openConsole && <ScanConsole key={openConsole.id} projectId={project.id} job={openConsole} onClose={() => setSelectedJob(undefined)}/>}
    {comparing && run && <AuditComparison key={run.id} root={root} current={run} candidates={baselines}
      onAsset={onInspectAsset} onFinding={onInspectFinding} onClose={() => setComparing(false)}/>}
  </section>
}
