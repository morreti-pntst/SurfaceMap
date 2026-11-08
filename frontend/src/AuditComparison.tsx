import {useEffect, useRef, useState} from 'react'
import {ArrowUpRight, Download, GitCompareArrows, X} from 'lucide-react'

type Run = {id: number; target: string; status: string; profile: string; completed_at: string | null}
type Asset = {id: number; type: string; value: string}
type Finding = {id: number; title: string; severity: string; target: string; review_state: string}
type Change = Asset & {kind: string; before: Record<string, unknown>[]; after: Record<string, unknown>[]}
type CheckChange = {
  tool: string; target: string; change: string; before: string | null; after: string | null
  before_version: string | null; after_version: string | null
}
type Delta<T> = {new_count: number; only_before_count: number; shared_count: number; new: T[]; only_before: T[]}
type Comparison = {
  baseline: Run; current: Run
  coverage: {aligned: boolean; notes: string[]; shared_checks: number; baseline_checks: number; current_checks: number;
    historical_membership: boolean; recovered_membership: boolean; historical_details: boolean; detail_checks: number;
    changed_checks: CheckChange[]; changed_check_count: number}
  assets: Delta<Asset>; findings: Delta<Finding>; changed_details: Change[]; changed_details_count: number; row_limit: number
}

type Tab = 'assets' | 'findings' | 'details'
const human = (value: string) => value.replaceAll('_', ' ')

function EvidenceRows({rows}: {rows: Record<string, unknown>[]}) {
  return <ul className="comparison-facts">
    {rows.map((row, index) => <li key={index}><dl>{Object.entries(row).map(([field, value]) => <div key={field}>
      <dt>{human(field)}</dt><dd>{Array.isArray(value) ? value.join(', ') : String(value)}</dd>
    </div>)}</dl></li>)}
  </ul>
}

function AssetList({title, rows, count, auditId, onInspect}: {
  title: string; rows: Asset[]; count: number; auditId: number; onInspect: (id: number, run: number) => void
}) {
  return <section className="comparison-group"><h3>{title} <span>{count}</span></h3>
    {rows.map(asset => <button className="comparison-row" key={asset.id} onClick={() => onInspect(asset.id, auditId)}>
      <small>{human(asset.type)}</small><code>{asset.value}</code><ArrowUpRight size={13}/>
    </button>)}
    {!rows.length && <p>No assets in this group.</p>}
    {count > rows.length && <p>Showing {rows.length} of {count} assets.</p>}
  </section>
}

function FindingList({title, rows, count, auditId, onInspect}: {
  title: string; rows: Finding[]; count: number; auditId: number; onInspect: (id: number, run: number) => void
}) {
  return <section className="comparison-group"><h3>{title} <span>{count}</span></h3>
    {rows.map(finding => <button className="comparison-row" key={finding.id} onClick={() => onInspect(finding.id, auditId)}>
      <span className={'severity severity-' + finding.severity}>{finding.severity}</span>
      <span>{finding.title}<small>{finding.target} · {human(finding.review_state)}</small></span><ArrowUpRight size={13}/>
    </button>)}
    {!rows.length && <p>No findings in this group.</p>}
    {count > rows.length && <p>Showing {rows.length} of {count} findings.</p>}
  </section>
}

export default function AuditComparison({root, current, candidates, onAsset, onFinding, onClose}: {
  root: string; current: Run; candidates: Run[]; onAsset: (id: number, run: number) => void
  onFinding: (id: number, run: number) => void; onClose: () => void
}) {
  const dialog = useRef<HTMLDialogElement>(null)
  const preferred = candidates.find(item => item.id < current.id && item.target === current.target && item.status === 'completed')
    ?? candidates.find(item => item.id < current.id && item.target === current.target)
    ?? candidates[0]
  const [baselineId, setBaselineId] = useState(preferred?.id)
  const [tab, setTab] = useState<Tab>('assets')
  const [data, setData] = useState<Comparison>()
  const [error, setError] = useState('')
  const [attempt, setAttempt] = useState(0)
  const url = baselineId === undefined ? '' : root + '/' + current.id + '/compare/' + baselineId
  useEffect(() => {
    if (dialog.current && !dialog.current.open) dialog.current.showModal()
  }, [])
  useEffect(() => {
    if (!url) return
    const controller = new AbortController()
    setError('')
    setData(undefined)
    void fetch(url, {signal: controller.signal, cache: 'no-store'}).then(async response => {
      const body = await response.json()
      if (!response.ok) throw new Error(typeof body.detail === 'string' ? body.detail : 'Could not compare audits.')
      if (!controller.signal.aborted) setData(body)
    }).catch(reason => { if (!controller.signal.aborted) setError(reason.message || 'Could not compare audits.') })
    return () => controller.abort()
  }, [url, attempt])

  const coverage = data?.coverage
  return <dialog className="operator-console comparison-dialog" ref={dialog} aria-labelledby="comparison-title"
    onCancel={event => {event.preventDefault(); onClose()}}>
    <header>
      <div><div className="eyebrow">EVIDENCE / AUDIT #{current.id}</div><h2 id="comparison-title"><GitCompareArrows size={17}/> Compare audit runs</h2></div>
      {data && <a className="button secondary compact" href={url + '?download=true'}><Download size={13}/> Comparison JSON</a>}
      <button className="icon-btn" aria-label="Close comparison" onClick={onClose}><X size={17}/></button>
    </header>
    <label className="comparison-baseline">Baseline run
      <select value={baselineId ?? ''} onChange={event => setBaselineId(Number(event.target.value))}>
        {candidates.map(run => <option key={run.id} value={run.id}>#{run.id} · {run.target} · {human(run.status)}</option>)}
      </select>
    </label>
    {error && <div className="console-error" role="alert">{error} <button className="button secondary compact" onClick={() => setAttempt(value => value + 1)}>Retry</button></div>}
    {!data && !error && <p role="status">Loading run evidence…</p>}
    {data && coverage && <>
      <section className={'comparison-coverage ' + (coverage.aligned ? '' : 'comparison-gap')}>
        <strong>{coverage.aligned ? 'Configured coverage aligns' : 'Coverage differs between runs'}</strong>
        <span>{coverage.shared_checks} matching completed checks · baseline #{data.baseline.id} ({coverage.baseline_checks}) · comparison #{data.current.id} ({coverage.current_checks})</span>
        {!!coverage.notes.length && <ul>{coverage.notes.map(note => <li key={note}>{note}</li>)}</ul>}
        {coverage.recovered_membership && <span>Asset membership for an older run was restored from retained scan artifacts.</span>}
        {coverage.historical_membership && <span>Asset history is incomplete. The groups below show only retained evidence.</span>}
        {coverage.historical_details && <span>Some older observations lack exact run lineage. Detail changes use only checks with evidence saved for both runs.</span>}
        {!!coverage.changed_checks.length && <details><summary>Check differences ({coverage.changed_check_count})</summary>
          <ul>{coverage.changed_checks.map(check => <li key={check.tool + check.target}>
            <b>{check.tool}</b> · <code>{check.target}</code> · {check.change} ({check.before ?? 'absent'} → {check.after ?? 'absent'})
            {check.before_version !== check.after_version && ' · versions ' + (check.before_version ?? '—') + ' → ' + (check.after_version ?? '—')}
          </li>)}</ul>
        </details>}
      </section>
      <div className="comparison-tabs">
        <button className="console-tab" aria-pressed={tab === 'assets'} onClick={() => setTab('assets')}>Assets · {data.assets.new_count + data.assets.only_before_count}</button>
        <button className="console-tab" aria-pressed={tab === 'findings'} onClick={() => setTab('findings')}>Findings · {data.findings.new_count + data.findings.only_before_count}</button>
        <button className="console-tab" aria-pressed={tab === 'details'} onClick={() => setTab('details')}>Changed details · {data.changed_details_count}</button>
      </div>
      {tab === 'assets' && <>
        <p className="comparison-note">{data.assets.shared_count} assets were observed in both runs. The inventory includes referenced links.</p>
        <div className="comparison-grid">
          <AssetList title="Only in comparison run" rows={data.assets.new} count={data.assets.new_count} auditId={current.id} onInspect={onAsset}/>
          <AssetList title="Only in baseline run" rows={data.assets.only_before} count={data.assets.only_before_count} auditId={data.baseline.id} onInspect={onAsset}/>
        </div>
      </>}
      {tab === 'findings' && <>
        <p className="comparison-note">{data.findings.shared_count} findings were observed in both runs. A finding seen only in the baseline still needs verification before closure.</p>
        <div className="comparison-grid">
          <FindingList title="Only in comparison run" rows={data.findings.new} count={data.findings.new_count} auditId={current.id} onInspect={onFinding}/>
          <FindingList title="Only in baseline run" rows={data.findings.only_before} count={data.findings.only_before_count} auditId={data.baseline.id} onInspect={onFinding}/>
        </div>
      </>}
      {tab === 'details' && <>
        <p className="comparison-note">Changes in HTTP, DNS or service observations from {coverage.detail_checks} checks with comparable recorded evidence.</p>
        {data.changed_details.map(item => <details className="comparison-detail" key={item.id + item.kind}>
          <summary>{human(item.kind)} · <code>{item.value}</code></summary>
          <div className="comparison-grid"><div><b>Baseline #{data.baseline.id}</b><EvidenceRows rows={item.before}/></div>
            <div><b>Comparison #{current.id}</b><EvidenceRows rows={item.after}/></div></div>
          <button className="button secondary compact" onClick={() => onAsset(item.id, current.id)}>Inspect on map <ArrowUpRight size={13}/></button>
        </details>)}
        {!data.changed_details.length && <div className="data-empty">No detail changes could be verified.</div>}
      </>}
    </>}
  </dialog>
}
