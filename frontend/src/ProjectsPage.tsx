import { useEffect, useRef, useState, type FormEvent } from 'react'
import { ArrowUpRight, ChevronDown, Copy, Download, Folder, Pencil, Plus, Settings2, Trash2, X } from 'lucide-react'

export type Project = {
  id: number
  name: string
  description: string
  created_at: string
  scopes: {id: number; value: string; kind: string; excluded: boolean}[]
}

export function ProjectSwitcher({projects, selected, onSelect, onManage, onCreate}: {
  projects: Project[]; selected: Project | null
  onSelect: (project: Project) => void; onManage: () => void; onCreate: () => void
}) {
  const root = useRef<HTMLDivElement>(null)
  const trigger = useRef<HTMLButtonElement>(null)
  const [open, setOpen] = useState(false)
  useEffect(() => {
    if (!open) return
    function outside(event: PointerEvent) {
      if (!root.current?.contains(event.target as Node)) setOpen(false)
    }
    document.addEventListener('pointerdown', outside)
    return () => document.removeEventListener('pointerdown', outside)
  }, [open])
  return <div className="project-switcher" ref={root} onKeyDown={event => {
    if (event.key === 'Escape') { setOpen(false); trigger.current?.focus() }
  }}>
    <button ref={trigger} className="workspace" aria-expanded={open} aria-label="Switch project" onClick={() => setOpen(!open)}>
      <span className="workspace-icon">{selected?.name.slice(0, 1).toUpperCase() ?? 'S'}</span>
      <span className="workspace-name"><b>{selected?.name ?? 'Select a project'}</b><small>Local workspace</small></span>
      <ChevronDown size={15}/>
    </button>
    {open && <div className="project-popover">
      <div className="popover-caption">WORKSPACES</div>
      <div className="project-popover-list">{projects.map(project => <button key={project.id}
        aria-current={project.id === selected?.id ? 'true' : undefined} onClick={() => {
          setOpen(false); onSelect(project); trigger.current?.focus()
        }}><Folder size={14}/><span>{project.name}</span></button>)}</div>
      <div className="project-popover-actions">
        <button onClick={() => {setOpen(false); onManage()}}><Settings2 size={14}/> Manage projects</button>
        <button onClick={() => {setOpen(false); onCreate()}}><Plus size={14}/> New project</button>
      </div>
    </div>}
  </div>
}

type Action = {type: 'edit' | 'duplicate' | 'delete'; project: Project}

function ProjectDialog({action, onClose, onSave, onDelete}: {
  action: Action; onClose: () => void; onSave: (project: Project, select: boolean) => void; onDelete: (id: number) => void
}) {
  const {type, project} = action
  const dialog = useRef<HTMLDialogElement>(null)
  const [name, setName] = useState(type === 'duplicate' ? (project.name.slice(0, 112) + ' copy') : project.name)
  const [description, setDescription] = useState(project.description)
  const [confirmation, setConfirmation] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  useEffect(() => { dialog.current?.showModal() }, [])
  const title = type === 'edit' ? 'Edit project' : type === 'duplicate' ? 'Duplicate project scope' : 'Delete project'
  async function submit(event: FormEvent) {
    event.preventDefault()
    if (busy || (type === 'delete' && confirmation !== project.name)) return
    setBusy(true)
    setError('')
    try {
      const root = '/api/projects/' + project.id
      const response = await fetch(type === 'duplicate' ? root + '/duplicate' : root, type === 'delete' ? {method: 'DELETE'} : {
        method: type === 'edit' ? 'PATCH' : 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({name, description}),
      })
      if (!response.ok) {
        const body = await response.json().catch(() => ({}))
        throw new Error(typeof body.detail === 'string' ? body.detail : 'The project could not be updated.')
      }
      if (type === 'delete') onDelete(project.id)
      else onSave(await response.json(), type === 'duplicate')
      onClose()
    } catch (failure) { setError((failure as Error).message) }
    finally { setBusy(false) }
  }

  return <dialog className="modal project-dialog" ref={dialog} aria-labelledby="project-dialog-title"
    onCancel={event => {event.preventDefault(); if (!busy) onClose()}}>
    <form onSubmit={submit}>
      <div className="modal-kicker">PROJECT MANAGEMENT</div><h2 id="project-dialog-title">{title}</h2>
      {type === 'delete' ? <>
        <p>This permanently removes <strong>{project.name}</strong> and its audits, assets, findings and scan files.</p>
        <label>Type the project name to confirm<input autoFocus value={confirmation} onChange={event => setConfirmation(event.target.value)}/></label>
      </> : <>
        {type === 'duplicate' && <p>Copies explicit allow and exclude rules into a new project. Its results and scan history start empty.</p>}
        <label>Project name<input autoFocus required maxLength={120} value={name} onChange={event => setName(event.target.value)}/></label>
        <label>Description<textarea rows={3} maxLength={2000} value={description} onChange={event => setDescription(event.target.value)}/></label>
      </>}
      {error && <div className="form-error" role="alert">{error}</div>}
      <div className="project-dialog-actions">
        <button type="button" className="button secondary" disabled={busy} onClick={onClose}><X size={14}/> Cancel</button>
        <button type="submit" className={'button ' + (type === 'delete' ? 'danger' : 'primary')}
          disabled={busy || (type === 'delete' ? confirmation !== project.name : !name.trim())}>
          {busy ? 'Working…' : type === 'delete' ? 'Delete project' : type === 'edit' ? 'Save changes' : 'Create duplicate'}
        </button>
      </div>
    </form>
  </dialog>
}

export default function ProjectsPage({projects, selected, onCreate, onOpen, onSave, onDelete}: {
  projects: Project[]; selected: Project | null; onCreate: () => void; onOpen: (project: Project) => void
  onSave: (project: Project, select: boolean) => void; onDelete: (id: number) => void
}) {
  const [action, setAction] = useState<Action>()
  const [query, setQuery] = useState('')
  const shown = projects.filter(project => [project.name, project.description].join(' ').toLowerCase().includes(query.trim().toLowerCase()))
  return <section className="workspace-page">
    <header className="page-heading">
      <div><div className="eyebrow"><span className="live-pulse"/> WORKSPACES</div><h1>Projects</h1>
        <p className="subtitle">Organize your assessments, reuse approved scope and export project evidence.</p></div>
      <button className="button primary" onClick={onCreate}><Plus size={15}/> New project</button>
    </header>
    <label className="project-filter">Filter projects<input value={query} onChange={event => setQuery(event.target.value)} placeholder="Search project names"/></label>
    <div className="project-card-grid">
      {shown.map(project => <article className="panel project-card" key={project.id}>
        <div className="project-card-heading">
          <span className="project-avatar">{project.name.slice(0, 1).toUpperCase()}</span>
          <div><h2>{project.name}</h2><small>{project.scopes.length} scope rules · {new Date(project.created_at).toLocaleDateString()}</small></div>
          {selected?.id === project.id && <span className="job-status job-completed">Selected</span>}
        </div>
        <p>{project.description || 'No description'}</p>
        <div className="project-card-actions">
          <button className="button primary compact" onClick={() => onOpen(project)}>Open project <ArrowUpRight size={13}/></button>
          <button className="button secondary compact" onClick={() => setAction({type: 'edit', project})}><Pencil size={13}/> Edit</button>
          <button className="button secondary compact" onClick={() => setAction({type: 'duplicate', project})}><Copy size={13}/> Duplicate scope</button>
          <a className="button secondary compact" href={'/api/projects/' + project.id + '/reports/json'}><Download size={13}/> Export JSON</a>
          <button className="button danger compact" onClick={() => setAction({type: 'delete', project})}><Trash2 size={13}/> Delete</button>
        </div>
      </article>)}
    </div>
    {!shown.length && <div className="panel data-empty">{projects.length ? 'No projects match this filter.' : 'Create your first project to define the scope.'}</div>}
    {action && <ProjectDialog action={action} onClose={() => setAction(undefined)} onSave={onSave} onDelete={onDelete}/>}
  </section>
}
