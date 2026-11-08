import { useEffect, useState } from 'react'
import { AlertTriangle, Check, RefreshCw, ShieldCheck } from 'lucide-react'

type Settings={automatic_updates:boolean;update_stable_releases:boolean;include_prereleases:boolean;check_updates_on_startup:boolean}
const initial:Settings={automatic_updates:true,update_stable_releases:true,include_prereleases:false,check_updates_on_startup:true}

export default function SettingsPage({nickname,onNickname}: {nickname:string;onNickname:(value:string)=>void}){
  const [localName,setLocalName]=useState(nickname)
  const [settings,setSettings]=useState(initial),[busy,setBusy]=useState(true),[saved,setSaved]=useState(false),[error,setError]=useState('')
  useEffect(()=>{void fetch('/api/settings/tools').then(async r=>{if(!r.ok)throw new Error('Could not load settings');setSettings({...initial,...await r.json()})}).catch(e=>setError(e.message)).finally(()=>setBusy(false))},[])
  async function save(){setBusy(true);setSaved(false);setError('');try{const r=await fetch('/api/settings/tools',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(settings)});const body=await r.json();if(!r.ok)throw new Error(body.detail??'Could not save settings');setSettings(body);setSaved(true)}catch(e){setError(e instanceof Error?e.message:'Could not save settings')}finally{setBusy(false)}}
  const toggle=(key:keyof Settings)=><button type="button" aria-pressed={settings[key]} disabled={key==='include_prereleases'} className={`setting-toggle ${settings[key]?'on':''}`} onClick={()=>{setSettings({...settings,[key]:!settings[key]});setSaved(false)}}><i/></button>
  return <section className="workspace-page settings-page"><div className="page-heading"><div><div className="eyebrow"><span className="live-pulse"/> SYSTEM <span className="eyebrow-sep">/</span> LOCAL CONFIGURATION</div><h1>Settings</h1><p className="subtitle">Configure startup checks and automatic lifecycle management for integrated tools.</p></div></div>
    <div className="panel settings-panel"><div className="panel-head"><div><div className="panel-title"><ShieldCheck size={15}/> Tool Manager policy</div><div className="panel-sub">Saved locally in the SurfaceMap database.</div></div></div>
      <div className="setting-row"><div><b>Automatic updates</b><span>Install or update missing pinned stable adapters when SurfaceMap starts.</span></div>{toggle('automatic_updates')}</div>
      <div className="setting-row"><div><b>Check updates on startup</b><span>Check installed tools during application startup.</span></div>{toggle('check_updates_on_startup')}</div>
      <div className="setting-row"><div><b>Stable releases only</b><span>The adapter manifest currently pins stable releases and checks compatibility before activation.</span></div>{toggle('update_stable_releases')}</div>
      <div className="setting-row setting-readonly"><div><b>Include prereleases</b><span>Prerelease adapters are not present in the current supported catalog.</span></div>{toggle('include_prereleases')}</div>
      {error&&<div className="form-error"><AlertTriangle size={13}/>{error}</div>}{saved&&<div className="settings-saved"><Check size={13}/> Settings saved</div>}
      <div className="settings-actions"><span><RefreshCw size={12}/> Pinned versions are managed in Tool Manager.</span><button className="button primary" disabled={busy} onClick={()=>void save()}>{busy?'Saving…':'Save settings'}</button></div>
    </div>
    <form className="panel settings-panel settings-about" onSubmit={event=>{
      event.preventDefault()
      const value=localName.trim()
      setLocalName(value)
      onNickname(value)
    }}>
      <div className="setting-row"><label className="scan-field">Local nickname
        <input maxLength={32} placeholder="Local operator" value={localName} onChange={event=>setLocalName(event.target.value)}/>
        <small>Stored in this browser. Leave blank to reset.</small>
      </label><button className="button secondary" disabled={localName===nickname}>Save nickname</button></div>
    </form>
    <div className="panel settings-panel settings-about">
      <div className="panel-head"><div><div className="panel-title">About SurfaceMap</div>
        <div className="panel-sub">Developed by morreti</div></div></div>
      <div className="setting-row"><div><b>Contact the developer</b><span>Advertising, suggestions, and general questions</span>
        <a className="text-action" href="mailto:alsocwa@proton.me">alsocwa@proton.me</a></div></div>
    </div>
  </section>
}
