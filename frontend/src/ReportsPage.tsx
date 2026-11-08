import { Download, FileJson2, FileSpreadsheet, Printer, ShieldCheck } from 'lucide-react'

type Project={id:number;name:string;description:string}

export default function ReportsPage({project}:{project:Project|null}){
  if(!project)return <section className="workspace-page"><div className="page-heading"><div><div className="eyebrow">REPORTING</div><h1>Reports</h1><p className="subtitle">Select a project to export its recorded evidence.</p></div></div><div className="panel data-empty">Create or select a project first.</div></section>
  const url=(format:string)=>`/api/projects/${project.id}/reports/${format}`
  return <section className="workspace-page reports-page">
    <div className="page-heading"><div><div className="eyebrow"><span className="live-pulse"/> REPORTING <span className="eyebrow-sep">/</span> {project.name}</div><h1>Assessment reports</h1><p className="subtitle">Export the project's current assets, relationships, findings, authorized scope, and recent scan activity.</p></div></div>
    <div className="report-grid"><article className="panel report-card"><FileJson2/><h2>Structured JSON</h2><p>Full project snapshot for handoff, automation, and offline analysis.</p><a className="button secondary" href={url('json')}><Download size={14}/> Download JSON</a></article><article className="panel report-card"><FileSpreadsheet/><h2>CSV inventory</h2><p>Spreadsheet friendly assets and findings with their type, status, and timestamps.</p><a className="button secondary" href={url('csv')}><Download size={14}/> Download CSV</a></article><article className="panel report-card"><Printer/><h2>PDF report</h2><p>Printable summary with Unicode support, scope, asset totals, and findings.</p><a className="button primary" href={url('pdf')}><Download size={14}/> Download PDF</a></article><article className="panel report-card"><Printer/><h2>HTML report</h2><p>Readable summary and findings table for review in a browser.</p><a className="button secondary" href={url('html')} target="_blank" rel="noreferrer"><Printer size={14}/> Open report</a></article></div>
    <div className="panel report-note"><ShieldCheck size={17}/><span>Reports include only evidence stored in <b>{project.name}</b>. Exported files do not run scans or make network requests.</span></div>
  </section>
}
