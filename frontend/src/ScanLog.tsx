import { useEffect, useRef, useState } from 'react'
import { Copy, Download, Terminal, X } from 'lucide-react'

type Diagnostic = {category: string; http_status: number | null}
type ScanDiagnostics = {
  status: string
  elapsed_seconds: number
  timeout_seconds: number
  progress: Record<string, string | number>
  events: string
  stderr: string
  stdout: string
  error: string
  command: string[]
  tool_id: string
  exit_code: number | null
  diagnostic?: Diagnostic
}
export type ConsoleJob = {id: number; status: string; label: string}
const activeStatuses = new Set(['queued', 'running', 'cancelling'])
const streams = [['events', 'Run events'], ['stderr', 'Tool diagnostics'], ['stdout', 'Tool output']] as const
type Stream = typeof streams[number][0]

export function formatCommand(command: string[]) {
  return command.map(arg => /^[\w:./,@+%=-]+$/.test(arg) ? arg : "'" + arg.replaceAll("'", "'\\''") + "'").join(' ')
}

function useDiagnostics(projectId: number, job: ConsoleJob, paused = false) {
  const [logs, setLogs] = useState<ScanDiagnostics>()
  const [error, setError] = useState('')
  const [retry, setRetry] = useState(0)
  const active = activeStatuses.has(job.status)
  useEffect(() => {
    if (paused) return
    const controller = new AbortController()
    let timer: number | undefined
    let failures = 0
    async function load() {
      let poll = active
      try {
        const response = await fetch('/api/projects/' + projectId + '/scan-jobs/' + job.id + '/logs', {
          signal: controller.signal, cache: 'no-store',
        })
        if (response.status === 404) {
          poll = false
          if (!controller.signal.aborted) {
            setLogs(undefined)
            setError('This scan is no longer available in this project.')
          }
          return
        }
        if (!response.ok) throw new Error('Could not load scanner diagnostics.')
        const data = await response.json()
        poll = activeStatuses.has(data.status)
        failures = 0
        if (!controller.signal.aborted) {
          setLogs(data)
          setError('')
        }
      } catch {
        failures += 1
        poll = failures < 4
        if (!controller.signal.aborted) setError(poll
          ? 'Connection to the console was interrupted. Retrying…'
          : 'Could not reconnect to the console. Use Reload logs to try again.')
      } finally {
        if (poll && !controller.signal.aborted) timer = window.setTimeout(load, failures ? failures * 2000 : 2000)
      }
    }
    void load()
    return () => { controller.abort(); window.clearTimeout(timer) }
  }, [projectId, job.id, active, paused, retry])
  return {logs, error, active: activeStatuses.has(logs?.status ?? job.status), reload: () => setRetry(attempt => attempt + 1)}
}

function ScanCounters({logs}: {logs: ScanDiagnostics}) {
  const {requests, total, errors, matched, rps, phase, phase_percent, phase_remaining_seconds} = logs.progress
  const remaining = Number(total) - Number(requests)
  const eta = remaining > 0 && Number(rps) > 0 ? Math.ceil(remaining / Number(rps) / 60) : null
  return <div className="console-counters">
    <span><b>{logs.elapsed_seconds}s</b> elapsed</span>
    <span><b>{logs.timeout_seconds / 60}m</b> limit</span>
    {phase !== undefined && <span><b>{phase}</b>{phase_percent !== undefined && ` · ${phase_percent}% of phase`}</span>}
    {phase_remaining_seconds !== undefined && <span><b>~{phase_remaining_seconds}s</b> left in phase</span>}
    {requests !== undefined && <span><b>{requests}{total !== undefined && ' / ' + total}</b> requests</span>}
    {rps !== undefined && <span><b>{rps}</b> req/s</span>}
    {errors !== undefined && <span><b>{errors}</b> request errors</span>}
    {matched !== undefined && <span><b>{matched}</b> matches</span>}
    {eta !== null && <span><b>~{eta}m</b> estimated</span>}
    {logs.exit_code != null && <span><b>{logs.exit_code}</b> exit code</span>}
  </div>
}

export function LiveScanProgress({projectId, job, onOpen}: {projectId: number; job: ConsoleJob; onOpen: () => void}) {
  const {logs, error} = useDiagnostics(projectId, job)
  const last = logs?.events.trim().split('\n').at(-1)
  return <div className="active-console-preview">
    <div><strong>{job.label}</strong><small>Scan #{job.id}{last && ' · ' + last.replace(/^\S+\s+/, '')}</small></div>
    <button className="button secondary compact" onClick={onOpen}><Terminal size={14}/> Open console</button>
    {logs && <ScanCounters logs={logs}/>}
    {error && <small role="status">{error}</small>}
  </div>
}

export default function ScanConsole({projectId, job, onClose}: {
  projectId: number; job: ConsoleJob; onClose: () => void
}) {
  const panel = useRef<HTMLDialogElement>(null)
  const output = useRef<HTMLPreElement>(null)
  const [stream, setStream] = useState<Stream>('events')
  const [paused, setPaused] = useState(false)
  const [follow, setFollow] = useState(true)
  const [message, setMessage] = useState('')
  const {logs, error, active, reload} = useDiagnostics(projectId, job, paused)
  const status = logs?.status ?? job.status
  const content = logs?.[stream] ?? ''
  useEffect(() => { panel.current?.showModal() }, [])
  useEffect(() => {
    if (output.current && follow) output.current.scrollTop = output.current.scrollHeight
  }, [content, follow])
  const transcript = logs && [
    formatCommand(logs.command ?? []),
    logs.error,
    ...streams.map(([key, title]) => title + '\n' + logs[key]),
  ].filter(Boolean).join('\n\n')
  async function copy() {
    if (!transcript) return
    try {
      await navigator.clipboard.writeText(transcript)
      setMessage('Copied console output.')
    } catch { setMessage('Clipboard access is unavailable. Download the log to keep a copy.') }
  }
  function download() {
    if (!transcript) return
    const url = URL.createObjectURL(new Blob([transcript], {type: 'text/plain;charset=utf-8'}))
    const link = document.createElement('a')
    link.href = url
    link.download = 'surfacemap-scan-' + job.id + '.log'
    link.click()
    window.setTimeout(() => URL.revokeObjectURL(url), 1000)
  }

  return <dialog className="operator-console" ref={panel} aria-labelledby="console-title"
    onCancel={event => { event.preventDefault(); onClose() }}>
    <header>
      <div><div className="eyebrow">EXECUTION / SCAN #{job.id}</div><h2 id="console-title">{job.label}</h2></div>
      <span className={'job-status job-' + status}>{status}</span>
      <button className="icon-btn" onClick={onClose} aria-label="Close console"><X size={18}/></button>
    </header>
    {logs?.command?.length ? <code className="console-command">{formatCommand(logs.command)}</code> : null}
    {logs && <ScanCounters logs={logs}/>}
    {logs?.error && <p className="console-error">{logs.error}</p>}
    {error && <p className="console-error" role="status">{error}</p>}
    <div className="console-toolbar">
      {streams.map(([key, title]) => <button className="console-tab" key={key} aria-pressed={stream === key}
        onClick={() => setStream(key)}>{title}</button>)}
      {active && <button className="button secondary compact" onClick={() => setPaused(!paused)}>{paused ? 'Resume feed' : 'Pause feed'}</button>}
      {error && !paused && <button className="button secondary compact" onClick={reload}>Reload logs</button>}
    </div>
    <pre ref={output} tabIndex={0} aria-label={streams.find(([key]) => key === stream)?.[1]}>
      {content || (active ? 'Waiting for output on this stream…' : 'No output on this stream.')}
    </pre>
    <footer>
      <label><input type="checkbox" checked={follow} onChange={event => setFollow(event.target.checked)}/> Follow output</label>
      <button className="button secondary compact" disabled={!transcript} onClick={() => void copy()}><Copy size={13}/> Copy log</button>
      <button className="button secondary compact" disabled={!transcript} onClick={download}><Download size={13}/> Download log</button>
      {message && <small role="status">{message}</small>}
    </footer>
  </dialog>
}
