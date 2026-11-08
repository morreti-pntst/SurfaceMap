import { useCallback, useEffect, useState } from 'react'
import { AlertTriangle, ArrowDown, ArrowUp, Check, Play, Plus, RefreshCw, Save, Square, Terminal, X } from 'lucide-react'
import ScanConsole from './ScanLog'

type Project = {id: number; name: string}
type Parameter = {name: string; label: string; type: string; default?: unknown; options?: string[] | Record<string, string>; min?: number; max?: number}
type Tool = {id: string; name: string; active_adapter: boolean; parameters: Parameter[]}
type Wordlist = {name: string; path: string}
type Step = {tool_id: string; options: Record<string, unknown>}
type Job = {id: number; tool_id: string; status: string}
type Run = {id: number; target: string; status: string; jobs: Job[]; error: string}
type Workflow = {id: number; name: string; steps: Step[]; runs: Run[]}

const active = (run: Run) => ['queued', 'running'].includes(run.status)

async function request<T>(url: string, fallback: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, {...init, cache: 'no-store'})
  const data = await response.json()
  if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : data.detail?.reason ?? fallback)
  return data
}

export default function WorkflowPage({project}: {project: Project | null}) {
  if (project) return <WorkflowWorkspace key={project.id} project={project}/>
  return <section className="workspace-page">
    <div className="page-heading"><div><div className="eyebrow">OPERATIONS</div><h1>Workflow Builder</h1>
      <p className="subtitle">Select or create a project before building a scoped workflow.</p></div></div>
    <div className="panel data-empty">No project selected.</div>
  </section>
}

function WorkflowWorkspace({project}: {project: Project}) {
  const [tools, setTools] = useState<Tool[]>([])
  const [workflows, setWorkflows] = useState<Workflow[]>([])
  const [wordlists, setWordlists] = useState<Wordlist[]>([])
  const [name, setName] = useState('Discovery and web checks')
  const [steps, setSteps] = useState<Step[]>([])
  const [targets, setTargets] = useState<Record<number, string>>({})
  const [consoleId, setConsoleId] = useState<number>()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [refreshError, setRefreshError] = useState('')
  const [message, setMessage] = useState('')
  const root = '/api/projects/' + project.id
  const workflowUrl = root + '/workflows'
  const running = workflows.some(workflow => workflow.runs.some(run =>
    active(run) || run.jobs.some(job => job.status === 'cancelling')))
  const consoleJob = workflows.flatMap(workflow => workflow.runs.flatMap(run => run.jobs)).find(job => job.id === consoleId)
  const toolName = (id: string) => tools.find(tool => tool.id === id)?.name ?? id

  const refresh = useCallback(async (signal?: AbortSignal) => {
    try {
      const rows = await request<Workflow[]>(workflowUrl, 'Could not load workflows.', {signal})
      if (!signal?.aborted) {setWorkflows(rows); setRefreshError('')}
    } catch {
      if (!signal?.aborted) setRefreshError('Could not refresh workflow history. Try Refresh.')
    }
  }, [workflowUrl])

  useEffect(() => {
    const controller = new AbortController()
    const {signal} = controller
    void refresh(signal)
    void Promise.all([
      request<Tool[]>('/api/tools', 'Could not load tool adapters.', {signal}),
      request<Wordlist[]>('/api/wordlists', 'Could not load managed wordlists.', {signal}),
    ]).then(([adapters, lists]) => {
      if (!signal.aborted) {setTools(adapters.filter(tool => tool.active_adapter)); setWordlists(lists)}
    }).catch(() => {
      if (!signal.aborted) setError('Could not load tool adapters or wordlists. Reload the page to retry.')
    })
    return () => controller.abort()
  }, [refresh])

  useEffect(() => {
    if (!running) return
    const controller = new AbortController()
    let timer: number
    async function poll() {
      await refresh(controller.signal)
      if (!controller.signal.aborted) timer = window.setTimeout(poll, 2500)
    }
    timer = window.setTimeout(poll, 2500)
    return () => {controller.abort(); window.clearTimeout(timer)}
  }, [refresh, running])

  function newStep(tool: Tool): Step {
    return {tool_id: tool.id, options: Object.fromEntries(tool.parameters.map(parameter => [parameter.name, parameter.default ?? '']))}
  }

  function addStep() {
    const tool = tools.find(item => item.id === 'subfinder') ?? tools[0]
    if (tool) setSteps([...steps, newStep(tool)])
  }

  function updateStep(index: number, step: Step) {
    setSteps(current => current.map((item, position) => position === index ? step : item))
  }

  function move(index: number, delta: number) {
    const destination = index + delta
    const next = [...steps]
    const [step] = next.splice(index, 1)
    next.splice(destination, 0, step)
    setSteps(next)
  }

  async function submit(url: string, payload: unknown, success: string, after?: () => void) {
    setBusy(true)
    setError('')
    setMessage('')
    try {
      await request(url, 'The workflow request failed.', {
        method: 'POST', headers: {'Content-Type': 'application/json'}, body: payload === undefined ? undefined : JSON.stringify(payload),
      })
      setMessage(success)
      after?.()
      await refresh()
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'The workflow request failed.')
    } finally {
      setBusy(false)
    }
  }

  return <section className="workspace-page workflow-page">
    <div className="page-heading"><div><div className="eyebrow"><span className="live-pulse"/> OPERATIONS / {project.name}</div>
      <h1>Workflow Builder</h1><p className="subtitle">Run tools in sequence on one approved target. Scope is checked before every step.</p>
    </div><button className="button secondary" onClick={() => void refresh()}><RefreshCw size={14}/> Refresh</button></div>
    {(error || refreshError) && <div className="form-error" role="alert"><AlertTriangle size={14}/>{error || refreshError}</div>}
    {message && <div className="settings-saved" role="status"><Check size={13}/>{message}</div>}
    <div className="workflow-layout">
      <section className="panel workflow-editor">
        <div className="panel-head"><div><div className="panel-title">New sequence</div>
          <div className="panel-sub">Configure up to eight tool steps.</div></div></div>
        <form className="workflow-form" onSubmit={event => {
          event.preventDefault()
          void submit(workflowUrl, {name, steps}, 'Workflow saved.', () => setSteps([]))
        }}>
          <label>Workflow name<input value={name} maxLength={120} required onChange={event => setName(event.target.value)}/></label>
          <div className="workflow-steps">{steps.map((step, index) => <div className="workflow-step" key={index}>
            <span className="step-number">{String(index + 1).padStart(2, '0')}</span>
            <select aria-label={'Tool for step ' + (index + 1)} value={step.tool_id} onChange={event => {
              const tool = tools.find(item => item.id === event.target.value)
              if (tool) updateStep(index, newStep(tool))
            }}>{tools.map(tool => <option key={tool.id} value={tool.id}>{tool.name}</option>)}</select>
            <div className="step-order">
              <button type="button" aria-label="Move up" disabled={index === 0} onClick={() => move(index, -1)}><ArrowUp size={13}/></button>
              <button type="button" aria-label="Move down" disabled={index === steps.length - 1} onClick={() => move(index, 1)}><ArrowDown size={13}/></button>
              <button type="button" aria-label="Remove step" onClick={() => setSteps(steps.filter((_, position) => index !== position))}><X size={13}/></button>
            </div>
            {tools.find(tool => tool.id === step.tool_id)?.parameters.map(parameter =>
              <label key={parameter.name}>{parameter.label}<WorkflowField parameter={parameter} wordlists={wordlists}
                value={step.options[parameter.name]}
                onChange={value => updateStep(index, {...step, options: {...step.options, [parameter.name]: value}})}/></label>)}
          </div>)}</div>
          <div className="workflow-editor-actions">
            <button type="button" className="button secondary" disabled={steps.length >= 8 || !tools.length} onClick={addStep}><Plus size={13}/> Add tool step</button>
            <button className="button primary" disabled={busy || !name.trim() || !steps.length}><Save size={13}/> Save workflow</button>
          </div>
        </form>
      </section>
      <section className="panel workflow-runs">
        <div className="panel-head"><div><div className="panel-title">Saved workflows</div>
          <div className="panel-sub">{workflows.length} sequences{running && ' · live updates'}</div></div></div>
        {workflows.map(workflow => <article className="workflow-card" key={workflow.id}>
          <div className="workflow-card-head"><b>{workflow.name}</b>
            <small>{workflow.steps.map((step, index) => (index + 1) + '. ' + toolName(step.tool_id)).join(' → ')}</small></div>
          <form className="workflow-run-form" onSubmit={event => {
            event.preventDefault()
            const target = targets[workflow.id]?.trim()
            if (target) void submit(workflowUrl + '/' + workflow.id + '/runs', {target}, 'Workflow queued.')
          }}>
            <input aria-label={'Target for ' + workflow.name} value={targets[workflow.id] ?? ''} required maxLength={1024}
              onChange={event => setTargets({...targets, [workflow.id]: event.target.value})} placeholder="Scoped hostname or URL"/>
            <button className="button primary compact" disabled={busy || running || !targets[workflow.id]?.trim()}><Play size={12}/> Run sequence</button>
          </form>
          {workflow.runs.map(run => <div className="workflow-run-row" key={run.id}>
            <span className={'job-status job-' + run.status}>{run.status}</span><code>{run.target}</code>
            <small>{run.jobs.filter(job => job.status === 'completed').length} / {workflow.steps.length} steps completed</small>
            {active(run) && <button className="button secondary compact" disabled={busy} onClick={() =>
              void submit(root + '/workflow-runs/' + run.id + '/cancel', undefined, 'Workflow stopped.')}><Square size={12}/> Stop</button>}
            {run.jobs.map((job, index) => <button key={job.id} className="button secondary compact" onClick={() => setConsoleId(job.id)}>
              <Terminal size={13}/> {index + 1}. {toolName(job.tool_id)} · {job.status}
            </button>)}
            {run.error && <span className="scan-error">{run.error}</span>}
          </div>)}
        </article>)}
        {!workflows.length && <div className="data-empty">Add steps to save your first workflow.</div>}
      </section>
    </div>
    {consoleJob && <ScanConsole key={consoleJob.id} projectId={project.id}
      job={{...consoleJob, label: toolName(consoleJob.tool_id)}} onClose={() => setConsoleId(undefined)}/>}
  </section>
}

function WorkflowField({parameter, wordlists, value, onChange}: {
  parameter: Parameter; wordlists: Wordlist[]; value: unknown; onChange: (value: unknown) => void
}) {
  if (parameter.type === 'wordlist') return <select required value={String(value ?? '')} onChange={event => onChange(event.target.value)}>
    <option value="">Choose a managed wordlist</option>
    {wordlists.map(list => <option key={list.path} value={list.path}>{list.name}</option>)}
  </select>
  if (parameter.type === 'multi-select') return <select multiple value={Array.isArray(value) ? value : []}
    onChange={event => onChange(Array.from(event.target.selectedOptions, option => option.value))}>
    {Array.isArray(parameter.options) && parameter.options.map(option => <option key={option} value={option}>{option}</option>)}
  </select>
  if (parameter.type === 'choice') return <select value={String(value ?? '')} onChange={event => onChange(event.target.value)}>
    {Object.entries(parameter.options ?? {}).map(([option, label]) => <option key={option} value={option}>{label}</option>)}
  </select>
  const numeric = parameter.type === 'number'
  return <input type={numeric ? 'number' : 'text'} min={parameter.min} max={parameter.max}
    value={String(value ?? '')} onChange={event => onChange(numeric && event.target.value !== '' ? Number(event.target.value) : event.target.value)}/>
}

