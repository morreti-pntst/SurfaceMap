import ScanConsole, {formatCommand, type ConsoleJob} from './ScanLog'
import { useEffect, useState } from 'react'
import { AlertTriangle, ArrowRight, Ban, Check, ChevronDown, List, Play, RefreshCw, Settings2, ShieldCheck, Square, Terminal, RotateCcw } from 'lucide-react'
import {isTcpwrapped, useTcpwrappedVisibility} from './tcpwrappedVisibility'

type Scope={id:number;value:string;kind:string;excluded:boolean}
type Project={id:number;name:string;scopes:Scope[]}
type Tool={id:string;name:string;category:string;description:string;version:string|null;latest_version:string;status:string;documentation:string;parameters:Array<Record<string,unknown>>;active_adapter:boolean;advanced_flags:string[];custom_command?:{example:string;flags:string[]}}
type Job={id:number;tool_id:string;target:string;status:string;command:string[];tool_version:string|null;retry_of_id:number|null;results_count:number;audit_run_id:number|null;retest_finding_id:number|null;options:Record<string,unknown>;result_summary:{diagnostic?:{category:string};warnings?:string[];finding_ids?:number[];failure_kind?:string;coverage_gap?:string;network?:NetworkResult;retest?:{outcome:string;reason:string}};artifact_path:string|null;stdout_excerpt:string;error:string;created_at:string;started_at:string|null;completed_at:string|null}
type Preview={tool_id:string;tool_name:string;target:string;command:string[];installed:boolean;tool_version:string|null;scope_checked:boolean;limits:{timeout_seconds:number;requests_per_second:number|null;max_concurrent_jobs:number}}
type Wordlist={name:string;path:string;bytes:number}
export type ScanSeed = {target: string; toolId?: string; mode?: string; options?: Record<string,unknown>; templateId?: string; severity?: string; retestFindingId?: number; expectedMatch?: string}


type NetworkResult = {
  total_rows: number
  wrapped_count?: number
  hosts: {addresses: string[]; hostnames: string[]; discovery_reason?: string}[]
  ports: {host: string; protocol?: string; port?: number; state: string; name?: string; product?: string; version?: string; method?: string; ostype?: string; reason?: string; count?: string; groups?: {ports: string; reason: string}[]}[]
}
type RunMode = {id: string; label: string; options?: Record<string, unknown>; raw?: string}
type SavedPreset = {name: string; tool: string; mode: string; options: Record<string, unknown>; raw: string}
const presetStorage = 'surfacemap.scan-presets'
const webTools = new Set(['httpx', 'nuclei', 'katana', 'ffuf'])
const runModes: Record<string, RunMode[]> = {
  nmap: [
    {id: 'services', label: 'Default TCP ports (1,000) and service versions', options: {mode: 'services', ports: ''}},
    {id: 'discovery', label: 'Discover live devices', options: {mode: 'discovery', ports: ''}},
    {id: 'ports', label: 'Scan specific ports or a range', options: {mode: 'ports', ports: ''}},
    {id: 'quick', label: 'Top 100 TCP ports', options: {mode: 'services', ports: ''}, raw: '--top-ports 100'},
    {id: 'full', label: 'All TCP ports · 1–65535', options: {mode: 'ports', ports: '1-65535'}},
  ],
  nuclei: [
    {id: 'default', label: 'Web vulnerability checks'},
    {id: 'exposure', label: 'Exposures and misconfigurations', raw: '-tags exposure,misconfig', options: {severity: ['info', 'low', 'medium', 'high', 'critical']}},
    {id: 'critical', label: 'High and critical severity', options: {severity: ['high', 'critical']}},
    {id: 'template', label: 'One template by ID'},
  ],
  httpx: [{id: 'default', label: 'Check HTTP response'}, {id: 'tech', label: 'Identify technologies and web server', raw: '-title -tech-detect -web-server'}],
  katana: [{id: 'default', label: 'Discover pages and routes'}, {id: 'deep', label: 'Extended crawl', options: {depth: 3}, raw: '-js-crawl'}],
  dnsx: [{id: 'default', label: 'Resolve A, AAAA and CNAME'}, {id: 'mail', label: 'Include MX and TXT records', raw: '-mx -txt'}, {id: 'ns', label: 'Include name servers', raw: '-ns'}],
  subfinder: [{id: 'default', label: 'Find subdomains'}, {id: 'recursive', label: 'Recursive sources', raw: '-recursive'}, {id: 'all', label: 'All available sources', raw: '-all'}],
  amass: [{id: 'default', label: 'Passive domain discovery'}],
  ffuf: [{id: 'default', label: 'Discover paths with a wordlist'}, {id: 'case', label: 'Skip wordlist comments', raw: '-ic'}],
}

function NetworkReport({network, url, hideTcpwrapped}: {network: NetworkResult; url: string; hideTcpwrapped: boolean}) {
  const ports = hideTcpwrapped ? network.ports.filter(port => !isTcpwrapped(port.name) && !isTcpwrapped(port.product)) : network.ports
  const hiddenRows = network.ports.length - ports.length
  return <details open className="network-report">
    <summary>Nmap results · {network.hosts.length} devices · {network.total_rows - hiddenRows} port rows</summary>
    {ports.length ? <div className="network-table"><table>
      <thead><tr><th>Device</th><th>Port</th><th>State</th><th>Service and version</th></tr></thead>
      <tbody>{ports.map((port, index) => <tr key={index}>
        <td>{port.host}</td><td>{port.port ? port.port + '/' + port.protocol : port.count + ' ports'}
          {port.groups?.filter(group => group.ports).map(group => <small key={group.reason}>{group.ports}</small>)}</td>
        <td><span className={'job-status ' + (port.state === 'open' ? 'job-completed' : 'job-blocked')}>{port.state}</span>
          {port.reason && <small>{port.reason}</small>}</td>
        <td>{port.method === 'table' ? <>Unidentified{port.name && <small>Port-number hint: {port.name}</small>}</>
          : [port.name, port.product, port.version].filter(Boolean).join(' · ') || (port.state === 'open' ? 'Unidentified' : '—')}
          {port.ostype && <small>OS indicator {port.ostype}</small>}</td>
      </tr>)}</tbody>
    </table></div> : <p>{hiddenRows ? 'No port rows match the current filter.' : 'This run recorded no open or filtered ports.'}</p>}
    {!!network.hosts.length && <ul>{network.hosts.map(host => <li key={host.addresses.join(',')}>{host.addresses.join(', ')} {host.hostnames.join(', ')}</li>)}</ul>}
    {network.total_rows > network.ports.length && <p>Showing {ports.length} rows. Download the report for the full list.</p>}
    {!hideTcpwrapped && !!network.wrapped_count && <p>{network.wrapped_count} tcpwrapped responses. The map and JSON report list these separately.</p>}
    <a className="artifact-link" href={url}>Download device and port report (JSON)</a>
  </details>
}


export default function ScanJobsPage({project, initialScan, onFinding}: {
  project: Project; initialScan?: ScanSeed; onFinding: (id: number) => void
}) {
  const root = '/api/projects/' + project.id + '/scan-jobs'
  const tcpwrapped = useTcpwrappedVisibility(project.id)
  const [tools, setTools] = useState<Tool[]>([])
  const [jobs, setJobs] = useState<Job[]>([])
  const [wordlists, setWordlists] = useState<Wordlist[]>([])
  const [toolId, setToolId] = useState(initialScan?.toolId ?? (initialScan?.templateId ? 'nuclei' : 'nmap'))
  const [runMode, setRunMode] = useState(initialScan?.mode ?? (initialScan?.templateId ? 'template' : ''))
  const [custom, setCustom] = useState(initialScan?.mode === 'custom')
  const [target, setTarget] = useState(initialScan?.target ?? '')
  const [options, setOptions] = useState<Record<string, unknown>>(initialScan?.templateId
    ? {template_id: initialScan.templateId, severity: [initialScan.severity ?? 'info'], rate: 2}
    : initialScan?.options ?? {})
  const [rawArguments, setRawArguments] = useState('')
  const [customCommand, setCustomCommand] = useState('')
  const [advanced, setAdvanced] = useState(false)
  const [preview, setPreview] = useState<Preview>()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [consoleId, setConsoleId] = useState<number>()
  const [presetName, setPresetName] = useState('')
  const [presets, setPresets] = useState<SavedPreset[]>(() => {
    try {
      const value = JSON.parse(localStorage.getItem(presetStorage) ?? '[]')
      return Array.isArray(value) ? value : []
    } catch { return [] }
  })
  const tool = tools.find(item => item.id === toolId)
  const modes = runModes[toolId] ?? []
  const mode = modes.find(item => item.id === runMode) ?? modes[0]
  const retestFindingId = initialScan?.retestFindingId
  const primaryParameters = tool?.parameters.filter(({name}) => retestFindingId ? name === 'rate'
    : name === 'wordlist' || (name === 'ports' && ['ports', 'full'].includes(mode?.id ?? ''))
      || (name === 'template_id' && mode?.id === 'template')) ?? []
  const advancedParameters = tool?.parameters.filter(param => !primaryParameters.includes(param)
    && param.name !== 'mode' && param.name !== 'template_id' && param.name !== 'timeout_minutes' && param.name !== 'user_agent'
    && (param.name !== 'ports' || mode?.id === 'services')) ?? []
  const allowedScopes = project.scopes.filter(rule => !rule.excluded)
  const active = (job: Job) => ['queued', 'running', 'cancelling'].includes(job.status)
  const openJob = jobs.find(job => job.id === consoleId)
  const consoleJob: ConsoleJob | undefined = openJob && {
    id: openJob.id, status: openJob.status, label: (tools.find(item => item.id === openJob.tool_id)?.name ?? openJob.tool_id) + ' · ' + openJob.target,
  }

  async function request<T>(url: string, init?: RequestInit): Promise<T> {
    const response = await fetch(url, {cache: 'no-store', ...init})
    if (!response.ok) {
      const body = await response.json().catch(() => ({}))
      const detail = body.detail
      throw new Error(typeof detail === 'string' ? detail
        : Array.isArray(detail) ? detail.map(item => item.msg).join('. ')
        : detail?.reason ?? 'Request failed (' + response.status + ')')
    }
    return response.json()
  }

  async function refreshJobs(signal?: AbortSignal) {
    const rows = await request<Job[]>(root, {signal})
    if (!signal?.aborted) setJobs(rows)
  }
  useEffect(() => {
    const controller = new AbortController()
    let timer: number | undefined
    async function poll() {
      try { await refreshJobs(controller.signal) }
      catch (failure) { if (!controller.signal.aborted) setError((failure as Error).message) }
      finally { if (!controller.signal.aborted) timer = window.setTimeout(poll, 3000) }
    }
    void poll()
    void Promise.all([
      request<Tool[]>('/api/tools', {signal: controller.signal}),
      request<Wordlist[]>('/api/wordlists', {signal: controller.signal}),
    ]).then(([tools, lists]) => {
      if (!controller.signal.aborted) {
        setTools(tools.filter(item => item.active_adapter))
        setWordlists(lists)
      }
    }).catch(failure => { if (!controller.signal.aborted) setError(failure.message) })
    return () => { controller.abort(); window.clearTimeout(timer) }
  }, [root])
  useEffect(() => setPreview(undefined), [toolId, target, options, rawArguments, runMode, custom, customCommand, project.scopes])

  function selectMode(id: string, requested?: string) {
    const entry = tools.find(item => item.id === id)
    const choices = runModes[id] ?? []
    const choice = choices.find(item => item.id === requested) ?? choices[0]
    setToolId(id)
    setRunMode(choice?.id ?? '')
    setCustom(requested === 'custom')
    setOptions({...Object.fromEntries((entry?.parameters ?? []).map(field => [String(field.name), field.default ?? ''])), ...choice?.options})
    setRawArguments(choice?.raw ?? '')
    setPresetName('')
    setError('')
  }

  function storePresets(next: SavedPreset[]) {
    try {
      localStorage.setItem(presetStorage, JSON.stringify(next))
      setPresets(next)
      setError('')
    } catch { setError('Could not save presets in this browser.') }
  }

  function savePreset() {
    const name = presetName.trim()
    if (!name) return
    const other = presets.filter(item => item.name !== name || item.tool !== toolId)
    if (other.length >= 50) {
      setError('Delete a saved preset before adding another.')
      return
    }
    storePresets([...other, {name, tool: toolId, mode: mode?.id ?? '', options, raw: rawArguments}])
    setPresetName(name)
  }

  function loadPreset(name: string) {
    const item = presets.find(entry => entry.tool === toolId && entry.name === name)
    if (!item) return
    setPresetName(item.name)
    setRunMode(item.mode)
    setOptions({...item.options})
    setRawArguments(item.raw)
    setAdvanced(true)
  }

  function field(name: string, value: unknown) {
    setOptions(previous => ({...previous, [name]: value}))
  }

  function insertExample() {
    const example = tool?.custom_command?.example
    if (!example) return
    const selectedScope = project.scopes.find(rule => !rule.excluded && ['domain', 'ip'].includes(rule.kind))
    const host = selectedScope?.value.replace(/^\*\./, '')
    const sample = host && !host.includes(':') ? example.replaceAll('example.com', host) : example
    setCustomCommand(sample)
  }

  function useWordlist(path: string) {
    if (!path) return
    if (!custom) {
      field('wordlist', path)
      return
    }
    const escaped = "'" + path.replaceAll("'", "'\\''") + "'"
    setCustomCommand(previous => previous.replace(/\s*-w(?:=|\s+)(?:"[^"]*"|'[^']*'|\S+)/, '') + ' -w ' + escaped)
  }

  async function uploadWordlist(file: File) {
    setError('')
    const data = new FormData()
    data.append('file', file)
    try {
      const wordlist = await request<Wordlist>('/api/wordlists', {method: 'POST', body: data})
      setWordlists(previous => [wordlist, ...previous.filter(item => item.path !== wordlist.path)])
      useWordlist(wordlist.path)
    } catch (failure) { setError((failure as Error).message) }
  }

  async function submit(previewOnly: boolean) {
    if (!previewOnly && !preview?.installed) return
    if (!custom && mode?.id === 'template' && !String(options.template_id ?? '').trim()) {
      setError('Enter the Nuclei template ID.')
      return
    }
    setError('')
    setBusy(true)
    const limits = ['nmap', 'nuclei'].includes(toolId)
      ? {timeout_minutes: options.timeout_minutes ?? (toolId === 'nmap' ? 10 : 15)} : {}
    const data = retestFindingId ? {tool_id: 'nuclei', target, retest_finding_id: retestFindingId, options: {rate: options.rate ?? 2}}
      : custom ? {tool_id: toolId, custom_command: customCommand, options: {...limits, user_agent: options.user_agent ?? ''}}
      : {tool_id: toolId, target, options: {...options, ...limits}, raw_arguments: rawArguments}
    const init = {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data)}
    try {
      if (previewOnly) setPreview(await request<Preview>(root + '/preview', init))
      else {
        const created = await request<Job>(root, init)
        setJobs(previous => [created, ...previous.filter(job => job.id !== created.id)])
        setConsoleId(created.id)
        setPreview(undefined)
      }
    } catch (failure) { setError((failure as Error).message) }
    finally { setBusy(false) }
  }

  async function jobAction(path: string) {
    setError('')
    setBusy(true)
    try {
      await request(path, {method: 'POST'})
      await refreshJobs()
    } catch (failure) { setError((failure as Error).message) }
    finally { setBusy(false) }
  }

  function prepareRetry(job: Job, lowRate: boolean, longer = false) {
    const previousTime = Number(job.options.timeout_minutes ?? 5)
    const timing = job.tool_id === 'nmap' ? {timeout_minutes: longer ? Math.min(60, previousTime * 2) : previousTime} : {}
    if (job.options.custom_command && !lowRate) {
      selectMode(job.tool_id, 'custom')
      setCustomCommand(String(job.options.custom_command))
      setOptions(previous => ({...previous, ...timing, user_agent: job.options.user_agent ?? ''}))
    } else {
      selectMode(job.tool_id, job.tool_id === 'nuclei' && job.options.template_id ? 'template'
        : job.tool_id === 'nmap' && job.options.mode === 'discovery' ? 'discovery'
        : job.tool_id === 'nmap' && job.options.ports ? 'ports' : undefined)
      setTarget(job.target)
      const {custom_command: _custom, raw_arguments, template_ids, time_budget_seconds, ...scanOptions} = job.options
      if (Array.isArray(template_ids) && typeof template_ids[0] === 'string') {
        setRunMode('template')
        scanOptions.template_id = template_ids[0]
      }
      if (typeof time_budget_seconds === 'number') scanOptions.timeout_minutes = time_budget_seconds / 60
      setOptions({...scanOptions, ...timing, ...(lowRate ? {rate: 1} : {})})
      setRawArguments(String(raw_arguments ?? ''))
      setAdvanced(true)
    }
    window.scrollTo({top: 0, behavior: 'smooth'})
  }

  function prepareNucleiConnectionCheck(job: Job) {
    selectMode('nuclei', 'template')
    setTarget(job.target)
    setOptions({template_id: 'http-missing-security-headers', severity: ['info'], rate: 1,
      concurrency: 1, request_timeout: 15, request_retries: 0, timeout_minutes: 5,
      user_agent: job.options.user_agent ?? ''})
    setAdvanced(true)
    window.scrollTo({top: 0, behavior: 'smooth'})
  }

  function wordlistPicker() {
    return <label className="scan-field">Managed wordlist
      <select value={custom ? '' : String(options.wordlist ?? '')} onChange={event => useWordlist(event.target.value)}>
        <option value="">{custom ? 'Insert a wordlist path' : 'Select a wordlist'}</option>
        {wordlists.map(list => <option value={list.path} key={list.path}>{list.name} · {(list.bytes / 1024).toFixed(1)} KiB</option>)}
      </select>
      <input type="file" accept=".txt,.list" aria-label="Upload a managed wordlist" onChange={event => {
        const file = event.target.files?.[0]
        if (file) void uploadWordlist(file)
      }}/>
      <small>UTF-8 text · up to 10 MiB · stored locally</small>
    </label>
  }

  function parameter(param: Record<string, unknown>) {
    const key = String(param.name)
    if (key === 'wordlist') return <div key={key}>{wordlistPicker()}</div>
    const value = options[key] ?? param.default ?? ''
    return <label className="scan-field" key={key}>{String(param.label)}
      {param.type === 'multi-select' ? <select multiple value={Array.isArray(value) ? value as string[] : []}
        onChange={event => field(key, Array.from(event.target.selectedOptions).map(option => option.value))}>
        {(param.options as string[]).map(choice => <option key={choice}>{choice}</option>)}
      </select> : <input value={String(value)} type={param.type === 'number' ? 'number' : 'text'}
        min={typeof param.min === 'number' ? param.min : undefined}
        max={typeof param.max === 'number' ? param.max : undefined}
        onChange={event => field(key, param.type === 'number' ? Number(event.target.value) : event.target.value)}/>}
      {typeof param.help === 'string' && <small>{param.help}</small>}
    </label>
  }

  return <section className="workspace-page scan-page">
    <header className="page-heading">
      <div><div className="eyebrow"><span className="live-pulse"/> OPERATIONS / {project.name}</div><h1>Scan Jobs</h1>
        <p className="subtitle">Run a preset or write your command. Preview the exact arguments and watch execution in the console.</p></div>
      <button className="button secondary" onClick={() => void refreshJobs().catch(failure => setError(failure.message))}><RefreshCw size={14}/> Refresh</button>
    </header>
    {initialScan?.templateId && <div className="panel audit-retest-note">
      <span>Exact retest · <code>{initialScan.templateId}</code>. Review the matched URL and fill any required query values.</span>
      {initialScan.expectedMatch && initialScan.expectedMatch !== initialScan.target && <span>Expected match · <code>{initialScan.expectedMatch}</code></span>}
      {retestFindingId && <button className="button secondary compact" onClick={() => onFinding(retestFindingId)}>Back to finding #{retestFindingId}</button>}
    </div>}
    {error && <div className="form-error" role="alert"><AlertTriangle size={14}/>{error}</div>}
    <div className="scan-layout">
      <section className="panel scan-config" aria-labelledby="new-scan-title">
        <div className="panel-head">
          <div className="scan-panel-title">
            <span className="scan-panel-icon"><Terminal size={18} aria-hidden="true"/></span>
            <div><h2 id="new-scan-title" className="panel-title">{retestFindingId ? 'Finding retest' : 'New scan'}</h2>
              <div className="panel-sub">Configure and validate a scan for this project.</div></div>
          </div>
        </div>
        <form className="scan-form" aria-busy={busy} onSubmit={event => {event.preventDefault(); void submit(true)}}>
          <fieldset className="scan-fields" disabled={busy}>
            <label className="scan-field">Tool<select value={tools.length ? toolId : ''} disabled={!tools.length || Boolean(retestFindingId)}
              onChange={event => {selectMode(event.target.value); setAdvanced(false)}}>
              {!tools.length && <option value="">No tools loaded</option>}
              {tools.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}
            </select></label>
            {tool?.custom_command && !retestFindingId && <div className="scan-mode" role="group" aria-label="Command mode">
              <button type="button" aria-pressed={!custom} onClick={() => setCustom(false)}>
                <List size={14} aria-hidden="true"/> Preset
              </button>
              <button type="button" aria-pressed={custom} onClick={() => setCustom(true)}>
                <Terminal size={14} aria-hidden="true"/> Custom command
              </button>
            </div>}
            {!custom && <label className="scan-field">Scenario<select value={mode?.id ?? ''} disabled={!tool || Boolean(retestFindingId)}
              onChange={event => selectMode(toolId, event.target.value)}>
              {!modes.length && <option value="">Default scan</option>}
              {modes.map(item => <option key={item.id} value={item.id}>{item.label}</option>)}
            </select></label>}
            {!custom && tool && !retestFindingId && <details className="scan-advanced">
              <summary>My presets</summary>
              <div className="scan-advanced-fields">
                {presets.some(item => item.tool === toolId) && <label className="scan-field">Load a preset
                  <select value="" onChange={event => loadPreset(event.target.value)}>
                    <option value="">Choose saved settings</option>
                    {presets.filter(item => item.tool === toolId).map(item => <option key={item.name}>{item.name}</option>)}
                  </select>
                </label>}
                <label className="scan-field">Preset name<input value={presetName} maxLength={48}
                  onChange={event => setPresetName(event.target.value)}/></label>
                <div className="scan-actions">
                  <button type="button" className="button secondary compact" disabled={!presetName.trim()} onClick={savePreset}>Save preset</button>
                  <button type="button" className="button secondary compact"
                    disabled={!presets.some(item => item.tool === toolId && item.name === presetName)}
                    onClick={() => {storePresets(presets.filter(item => item.tool !== toolId || item.name !== presetName)); setPresetName('')}}>Delete preset</button>
                </div>
                <small>Presets save tool options in this browser. Choose the target for each run.</small>
              </div>
            </details>}
            {custom ? <div className="command-editor">
              <label className="scan-field"><span>Command arguments <code>{toolId}</code></span>
                <textarea aria-label="Command arguments" rows={4} value={customCommand} maxLength={2048} required
                  spellCheck={false} onChange={event => setCustomCommand(event.target.value)} placeholder={tool?.custom_command?.example}/>
                <small>Enter the arguments after the executable, including one target. SurfaceMap supplies output and execution limits.</small>
              </label>
              <div className="command-links">
                <button type="button" className="button secondary compact" onClick={insertExample}>Insert example</button>
                {tool?.documentation && <a href={tool.documentation} target="_blank" rel="noreferrer">Tool documentation</a>}
              </div>
              {toolId === 'ffuf' && wordlistPicker()}
              <details><summary>Supported flags</summary><div className="command-flag-list">
                {tool?.custom_command?.flags.map(flag => <code key={flag}>{flag}</code>)}
              </div></details>
            </div> : <>
              <label className="scan-field">{mode?.id === 'discovery' ? 'IP address or CIDR' : 'Target'}
                <input required value={target} onChange={event => setTarget(event.target.value)} autoCapitalize="none" spellCheck={false}
                  placeholder={mode?.id === 'discovery' ? '192.168.1.0/24' : 'example.com'}/>
                {mode?.id === 'discovery' && <small>Lists devices that respond to probes from Docker.</small>}
              </label>
              {primaryParameters.map(parameter)}
              {!retestFindingId && tool && (advancedParameters.length > 0 || tool.advanced_flags.length > 0) && <div className="scan-advanced">
                <button type="button" className="scan-advanced-toggle" aria-expanded={advanced} aria-controls="scan-advanced-fields"
                  onClick={() => setAdvanced(!advanced)}>
                  <Settings2 size={14} aria-hidden="true"/> Advanced options <ChevronDown size={14} aria-hidden="true"/>
                </button>
                <div id="scan-advanced-fields" className="scan-advanced-fields" hidden={!advanced}>
                  {advanced && advancedParameters.map(parameter)}
                  {advanced && tool.advanced_flags.length > 0 && <label className="scan-field">Additional flags
                    <input value={rawArguments} onChange={event => setRawArguments(event.target.value)}
                      placeholder={tool.advanced_flags.slice(0, 3).join(' ')}/>
                    <small>{tool.advanced_flags.join(', ')}</small>
                  </label>}
                </div>
              </div>}
            </>}
            {!retestFindingId && webTools.has(toolId) && <label className="scan-field">User-Agent (optional)
              <input value={String(options.user_agent ?? '')} maxLength={512} placeholder="Tool default"
                onChange={event => field('user_agent', event.target.value)}/>
            </label>}
            {!retestFindingId && ['nmap', 'nuclei'].includes(toolId) && <label className="scan-field">Maximum run time (minutes)
              <input type="number" min={toolId === 'nmap' ? 1 : 5} max={60} required
                value={String(options.timeout_minutes ?? (toolId === 'nmap' ? 10 : 15))}
                onChange={event => field('timeout_minutes', event.target.value === '' ? '' : Number(event.target.value))}/>
              <small>Applies to the whole scanner job.</small>
            </label>}
            <div className="scope-summary"><b><ShieldCheck size={14} aria-hidden="true"/> Project scope</b>
              <span>{allowedScopes.length} allowed · {project.scopes.length - allowedScopes.length} excluded</span>
              {project.scopes.length ? project.scopes.map(rule => <code className={rule.excluded ? 'scope-out' : 'scope-in'} key={rule.id}>
                {rule.kind === 'all' && !rule.excluded ? 'Unrestricted scope' : `${rule.excluded ? '−' : '+'} ${rule.value} · ${rule.kind}`}
              </code>) : <strong>Add an allowed domain, IP or CIDR in the project scope panel.</strong>}
            </div>
            {preview && <div className={'scan-preview ' + (preview.installed ? '' : 'preview-warning')} role="status">
              <div><b>Scope validated</b><span>{preview.target} · {preview.limits.timeout_seconds / 60}m limit
                {preview.limits.requests_per_second && ' · ' + preview.limits.requests_per_second + ' req/s'}</span></div>
              <pre>{formatCommand(preview.command)}</pre>
              {!preview.installed && <strong>Install the pinned adapter version from Tool Manager.</strong>}
            </div>}
            <div className="scan-actions">
              <button type="submit" className={'button ' + (preview ? 'secondary' : 'primary')} disabled={!tool || !(custom ? customCommand.trim() : target.trim())}><Terminal size={14}/> Preview command</button>
              {preview && <button type="button" className="button primary" disabled={!preview.installed} onClick={() => void submit(false)}><Play size={14}/> Start scan</button>}
            </div>
          </fieldset>
        </form>
      </section>
      <section className="panel scan-jobs-panel" aria-labelledby="scan-history-title">
        <div className="panel-head"><div className="scan-panel-title">
          <span className="scan-panel-icon"><List size={18} aria-hidden="true"/></span>
          <div><h2 id="scan-history-title" className="panel-title">Project runs</h2><div className="panel-sub">{jobs.length} recorded jobs</div></div>
        </div>
          <div className="scan-actions">
            {jobs.some(job => job.tool_id === 'nmap') && <button className="button secondary compact" onClick={tcpwrapped.toggle}>
              {tcpwrapped.hidden ? 'Show tcpwrapped ports' : 'Hide tcpwrapped ports'}
            </button>}
            <button className="button danger compact" disabled={busy || !jobs.some(active)} onClick={() => void jobAction('/api/scan-jobs/stop-all')}><Square size={12}/> Stop all scans</button>
          </div>
        </div>
        {jobs.length ? jobs.map(job => {
          const hideTcpwrapped = job.tool_id === 'nmap' && tcpwrapped.hidden
          const warnings = (job.result_summary?.warnings ?? []).filter(warning =>
            warning !== job.result_summary?.coverage_gap && (!hideTcpwrapped || !isTcpwrapped(warning)))
          return <article className="scan-job-row" key={job.id}>
          <div className="scan-job-head"><b>{tools.find(item => item.id === job.tool_id)?.name ?? job.tool_id}</b>
            <span className={'job-status job-' + (job.result_summary?.coverage_gap ? 'partial' : job.status)}>
              {job.result_summary?.coverage_gap ? 'Partial coverage' : job.result_summary?.failure_kind === 'blocked' ? 'Access check stopped' : job.status}
            </span>
            {job.audit_run_id && <small>Audit #{job.audit_run_id}</small>}
            {job.retest_finding_id && <small>Retest of finding #{job.retest_finding_id}</small>}
            <time>{new Date(job.created_at).toLocaleString()}</time>
            {['queued', 'running'].includes(job.status) && <button className="icon-btn" aria-label="Cancel scan" onClick={() => void jobAction(root + '/' + job.id + '/cancel')}><Ban size={14}/></button>}
          </div>
          <code>{job.target}</code>
          <small>Scan #{job.id} · {job.tool_version} · {job.results_count} normalized results</small>
          {job.error && <div className="scan-error"><AlertTriangle size={12}/>{job.error}</div>}
          {job.result_summary?.coverage_gap && <small className="scan-error">{job.result_summary.coverage_gap}</small>}
          {job.result_summary?.retest && <small className="retest-summary">{job.result_summary.retest.reason}</small>}
          <div className="scan-actions">
            <button className="button secondary compact" onClick={() => setConsoleId(job.id)}><Terminal size={13}/> Console</button>
            {!job.retest_finding_id && job.tool_id === 'nuclei' && job.result_summary?.coverage_gap &&
              <button className="button secondary compact" onClick={() => prepareNucleiConnectionCheck(job)}>Prepare single-template check</button>}
            {job.tool_id === 'nmap' && job.result_summary?.coverage_gap?.startsWith('Nmap did not report a reachable host') &&
              <button className="button secondary compact" onClick={() => {
                selectMode('nmap', 'custom')
                setCustomCommand('-Pn -sV ' + job.target)
                setOptions(previous => ({...previous, timeout_minutes: job.options.timeout_minutes ?? 10}))
                window.scrollTo({top: 0, behavior: 'smooth'})
              }}>Prepare retry with -Pn</button>}
            {job.tool_id === 'nmap' && Number(job.options.timeout_minutes ?? 5) < 60 &&
              (job.result_summary?.failure_kind === 'timeout' || job.result_summary?.warnings?.some(warning => warning.includes('per-host time limit'))) &&
              <button className="button secondary compact" onClick={() => prepareRetry(job, false, true)}>Prepare longer retry</button>}
            {job.retest_finding_id ? <button className="button secondary compact" onClick={() => onFinding(job.retest_finding_id!)}>Open finding</button>
              : ['failed', 'cancelled'].includes(job.status) && <>
              <button className="button secondary compact" onClick={() => prepareRetry(job, false)}><RotateCcw size={13}/> Edit retry</button>
              {job.result_summary?.diagnostic?.category === 'rate_limit' && !job.options.custom_command &&
                <button className="button secondary compact" onClick={() => prepareRetry(job, true)}>Prepare 1 req/s retry</button>}
            </>}
          </div>
          {warnings.length ? <details><summary>Import warnings</summary><ul>
            {warnings.map((warning, index) => <li key={index}>{warning}</li>)}
          </ul></details> : null}
          {job.result_summary?.network && <NetworkReport network={job.result_summary.network}
            url={root + '/' + job.id + '/network-report'} hideTcpwrapped={hideTcpwrapped}/>}
          {job.artifact_path && job.status === 'completed' && <a className="artifact-link" href={root + '/' + job.id + '/artifact'}><ArrowRight size={12}/> Download scanner output</a>}
          </article>
        }) : <div className="data-empty"><Check size={15}/> Preview and start your first scan.</div>}
      </section>
    </div>
    {consoleJob && <ScanConsole key={consoleJob.id} projectId={project.id} job={consoleJob} onClose={() => setConsoleId(undefined)}/>}
  </section>
}
