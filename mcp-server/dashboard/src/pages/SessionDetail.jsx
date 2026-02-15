import { useState, useEffect, useRef, useCallback } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  ArrowLeft, Shield, FileCheck, Activity, Eye, Network, Scale,
  AlertTriangle, CheckCircle2, XCircle, Hash, Clock, ChevronDown, ChevronRight,
  Lock, Send, Brain, Zap, Terminal, Download,
  User, Bot, Filter, DollarSign, GitBranch,
} from 'lucide-react'
import {
  fetchSessionData, fetchOntologyExport, riskBadge, formatTime, shortHash, analyzeSession,
  getRiskLevel, getOwaspItems, getDriftAnomalies,
  riskColor, riskTextColor, statusBadge, downloadJSON, downloadCSV, downloadOntology,
} from '../api'

const TABS = [
  { id: 'overview', label: 'Overview', icon: Eye },
  { id: 'trace', label: 'Trace Tree', icon: Activity },
  { id: 'provenance', label: 'Provenance', icon: Hash },
  { id: 'security', label: 'Security', icon: Shield },
  { id: 'flows', label: 'Data Flows', icon: Network },
  { id: 'governance', label: 'Governance', icon: Scale },
  { id: 'ai', label: 'AI Analysis', icon: Brain },
]

export default function SessionDetail() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [tab, setTab] = useState('overview')

  useEffect(() => {
    setLoading(true)
    fetchSessionData(id)
      .then(setData)
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [id])

  if (loading) return <div className="flex items-center justify-center h-full"><div className="w-5 h-5 border-2 border-brand border-t-transparent rounded-full animate-spin" /></div>
  if (error) return <div className="flex items-center justify-center h-full"><div className="card p-6 text-center"><XCircle size={28} className="text-danger/40 mx-auto mb-2" /><p className="text-xs text-t-tertiary">{error}</p></div></div>
  if (!data) return null

  const risk = data.risk || {}
  const v = data.verification || {}

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="px-5 py-3 flex-shrink-0 bg-surface border-b border-white/[0.04]">
        <div className="flex items-center justify-between mb-2">
          <button onClick={() => navigate('/sessions')}
            className="text-xxs text-t-quaternary hover:text-t-secondary flex items-center gap-1 transition-colors">
            <ArrowLeft size={11} /> Sessions
          </button>
          <div className="flex items-center gap-1.5">
            <button onClick={() => downloadJSON(data)} className="btn-ghost text-xxs"><Download size={10} /> JSON</button>
            <button onClick={() => downloadCSV(data.records)} className="btn-ghost text-xxs"><Download size={10} /> CSV</button>
            <button onClick={() => fetchOntologyExport(id).then(downloadOntology).catch(e => alert('Ontology export failed: ' + e.message))} className="btn-ghost text-xxs"><Network size={10} /> Ontology</button>
          </div>
        </div>
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-md font-semibold font-mono text-t-primary">{data.session_id}</h1>
            <div className="flex items-center gap-2.5 mt-0.5 text-xxs text-t-quaternary">
              <span>{data.records?.length || 0} records</span>
              <span>·</span>
              <span>{data.session_log?.length || 0} events</span>
              <span>·</span>
              {v.valid
                ? <span className="text-emerald-400 flex items-center gap-0.5"><CheckCircle2 size={10} /> Verified</span>
                : <span className="text-red-400 flex items-center gap-0.5"><XCircle size={10} /> Invalid</span>}
            </div>
          </div>
          <span className={`badge ${riskBadge(getRiskLevel(risk))}`}>Risk: {risk.risk_score ?? 0}/100</span>
        </div>

        {/* Tabs */}
        <div className="flex gap-px mt-3 -mb-3">
          {TABS.map(t => (
            <button key={t.id} onClick={() => setTab(t.id)}
              className={`flex items-center gap-1 px-2.5 py-1.5 text-xs transition-all ${
                tab === t.id
                  ? 'text-brand font-medium border-b-2 border-brand'
                  : 'text-t-quaternary hover:text-t-tertiary border-b-2 border-transparent'
              }`}>
              <t.icon size={12} /> {t.label}
            </button>
          ))}
        </div>
      </div>

      <div className="flex-1 overflow-auto p-5">
        {tab === 'overview' && <OverviewTab data={data} />}
        {tab === 'trace' && <TraceTreeTab data={data} />}
        {tab === 'provenance' && <ProvenanceTab data={data} />}
        {tab === 'security' && <SecurityTab data={data} />}
        {tab === 'flows' && <DataFlowsTab data={data} />}
        {tab === 'governance' && <GovernanceTab data={data} />}
        {tab === 'ai' && <AIAnalysisTab data={data} />}
      </div>
    </div>
  )
}

/* ══════════ OVERVIEW ══════════ */
function OverviewTab({ data }) {
  const risk = data.risk || {}, v = data.verification || {}, ont = data.ontology || {}
  const df = ont.data_flow || {}, pr = ont.prompt_response || {}, xs = ont.cross_session_links || {}
  const patterns = risk.patterns || []

  return (
    <div className="space-y-4 max-w-5xl">
      <div className="grid grid-cols-4 gap-2.5">
        <SC label="Risk Score" value={`${risk.risk_score ?? 0}/100`} color={riskTextColor(risk.risk_score)} />
        <SC label="Records" value={data.records?.length || 0} />
        <SC label="Events" value={data.session_log?.length || 0} />
        <SC label="Merkle Root" value={shortHash(v.merkle_root)} mono />
      </div>

      <div className="grid grid-cols-2 gap-2.5">
        <div className="card p-4">
          <div className="section-label mb-2">Risk Gauge</div>
          <div className="flex items-center justify-center">
            <div className="relative w-24 h-24">
              <svg viewBox="0 0 120 120" className="w-full h-full">
                <circle cx="60" cy="60" r="48" fill="none" stroke="rgba(255,255,255,0.04)" strokeWidth="7" />
                <circle cx="60" cy="60" r="48" fill="none" stroke={riskColor(risk.risk_score)}
                  strokeWidth="7" strokeDasharray={`${(risk.risk_score||0)*3.01} 301`}
                  strokeLinecap="round" transform="rotate(-90 60 60)"
                  style={{filter:`drop-shadow(0 0 6px ${riskColor(risk.risk_score)}40)`}} />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className={`text-xl font-black ${riskTextColor(risk.risk_score)}`}>{risk.risk_score??0}</span>
                <span className="text-micro text-t-quaternary">/100</span>
              </div>
            </div>
          </div>
          <div className="text-center mt-1 text-xxs text-t-quaternary">{patterns.length} patterns · {risk.engine||'graphrag'}</div>
        </div>
        <div className="card p-4 space-y-2">
          <div className="section-label">Knowledge Graph</div>
          <QS label="Nodes" val={ont.total_nodes||0} />
          <QS label="Edges" val={ont.total_edges||0} />
          <QS label="Entities" val={df.entities_created||0} />
          <QS label="Prompt Entities" val={pr.prompt_entities||0} />
          <QS label="Cross-Session" val={xs.same_as_edges||0} />
        </div>
      </div>

      {(pr.injection_suspects||0) > 0 && (
        <div className="card p-3 border-danger/20" style={{boxShadow:'0 0 15px rgba(239,68,68,0.08)'}}>
          <div className="flex items-center gap-1.5 text-xs text-red-400 font-medium">
            <AlertTriangle size={12} /> {pr.injection_suspects} Prompt Injection Suspect(s) Detected
          </div>
        </div>
      )}

      <div className={`card p-3 ${v.valid?'':'border-danger/20'}`}>
        <div className="flex items-center gap-2">
          {v.valid ? <CheckCircle2 size={15} className="text-emerald-400" /> : <XCircle size={15} className="text-red-400" />}
          <span className={`text-sm font-medium ${v.valid?'text-emerald-400':'text-red-400'}`}>
            {v.valid ? 'Chain integrity verified — no tampering' : (v.error || 'Chain compromised')}
          </span>
        </div>
        {v.merkle_root && <div className="hash-text mt-1.5 ml-7">Merkle: {v.merkle_root}</div>}
      </div>
    </div>
  )
}

/* ══════════ TRACE TREE (LangSmith style) ══════════ */
function TraceTreeTab({ data }) {
  const events = data.session_log || []
  const risk = data.risk || {}
  const suspIdx = new Set((risk.causal_chains||[]).filter(c=>c.is_risky).flatMap(c=>c.indices||[]))
  const [selected, setSelected] = useState(null)
  const [filter, setFilter] = useState('all')
  const [limit, setLimit] = useState(200)

  const FILTERS = [
    { key:'all', label:'All', icon:Filter, count:events.length },
    { key:'message/user', label:'User', icon:User },
    { key:'message/assistant', label:'Assistant', icon:Bot },
    { key:'thinking', label:'Thinking', icon:Brain },
    { key:'tool_call', label:'Tool Call', icon:Terminal },
    { key:'tool_result', label:'Result', icon:FileCheck },
    { key:'suspicious', label:'Suspicious', icon:AlertTriangle },
  ]

  const evtType = (e) => e.type==='message'&&e.role ? `message/${e.role}` : e.type||'unknown'
  const counts = {}
  FILTERS.forEach(f => {
    if (f.key==='all') counts[f.key]=events.length
    else if (f.key==='suspicious') counts[f.key]=suspIdx.size
    else counts[f.key]=events.filter(e=>evtType(e)===f.key).length
  })

  const filtered = events.map((e,i)=>({...e,_i:i}))
    .filter(e=>filter==='all'||(filter==='suspicious'?suspIdx.has(e._i):evtType(e)===filter))
    .slice(0,limit)

  const iconFor = (t,r) => {
    if (t==='tool_call') return Terminal
    if (t==='tool_result') return FileCheck
    if (t==='message'&&r==='user') return User
    if (t==='message'&&r==='assistant') return Bot
    if (t==='thinking') return Brain
    return Activity
  }
  const colorFor = (t,r) => {
    if (t==='tool_call') return 'text-blue-400'
    if (t==='tool_result') return 'text-info'
    if (t==='message'&&r==='user') return 'text-emerald-400'
    if (t==='message'&&r==='assistant') return 'text-accent-violet'
    if (t==='thinking') return 'text-warning'
    return 'text-t-tertiary'
  }

  const summary = (e) => {
    if (e.type==='tool_call') return e.tool_name||e.name||'Tool Call'
    if (e.type==='tool_result') return (e.content||e.result||'').substring(0,80)
    if (e.type==='message'&&e.role==='user') return (e.content||'').substring(0,80)
    if (e.type==='message'&&e.role==='assistant') return (e.content||'').substring(0,80)
    if (e.type==='thinking') return (e.content||'').substring(0,80)
    return e.content?.substring(0,80)||e.type||'-'
  }

  return (
    <div className="flex gap-3 max-w-full" style={{height:'calc(100vh - 180px)'}}>
      {/* Left: Tree */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Filters */}
        <div className="flex items-center gap-1 mb-2 flex-wrap flex-shrink-0">
          {FILTERS.map(f=>{
            const I=f.icon; const c=counts[f.key]||0
            return (
              <button key={f.key} onClick={()=>setFilter(f.key)}
                className={`flex items-center gap-1 px-2 py-1 rounded text-xxs font-medium transition-all ${
                  filter===f.key
                    ? 'bg-brand/15 text-brand ring-1 ring-brand/25'
                    : 'text-t-quaternary hover:text-t-tertiary bg-raised/50'
                }`}>
                <I size={10}/>{f.label}<span className="text-micro opacity-60">{c}</span>
              </button>
            )
          })}
        </div>
        {/* Entries */}
        <div className="flex-1 overflow-auto space-y-px">
          {filtered.map(e=>{
            const I=iconFor(e.type,e.role), isSusp=suspIdx.has(e._i), isSel=selected?._i===e._i
            return (
              <button key={e._i} onClick={()=>setSelected(isSel?null:e)}
                className={`w-full text-left px-2.5 py-1.5 rounded flex items-center gap-2 transition-all text-xs ${
                  isSel ? 'bg-brand/10 border border-brand/25' :
                  isSusp ? 'bg-danger/5 border border-danger/15 hover:border-danger/25' :
                  'border border-transparent hover:bg-raised'
                }`}>
                <I size={12} className={`${colorFor(e.type,e.role)} flex-shrink-0`} />
                <span className="text-xxs text-t-quaternary font-mono w-5 text-right flex-shrink-0">{e._i+1}</span>
                <span className={`text-xxs font-mono w-16 flex-shrink-0 ${colorFor(e.type,e.role)}`}>
                  {e.type==='message'?e.role:e.type}
                </span>
                <span className="text-t-secondary truncate flex-1">{summary(e)}</span>
                {isSusp && <AlertTriangle size={10} className="text-danger flex-shrink-0" />}
              </button>
            )
          })}
          {filtered.length>=limit && (
            <button onClick={()=>setLimit(l=>l+200)}
              className="w-full py-1.5 text-xxs text-brand hover:text-accent-indigo bg-raised/50 rounded">
              Load more…
            </button>
          )}
        </div>
      </div>

      {/* Right: Detail Panel (LangSmith style) */}
      {selected && (
        <div className="w-80 flex-shrink-0 card p-0 flex flex-col overflow-hidden">
          <DetailPanel event={selected} onClose={()=>setSelected(null)} />
        </div>
      )}
    </div>
  )
}

function DetailPanel({ event: e, onClose }) {
  const [tab, setTab] = useState('input')
  const tabs = ['input','output','metadata']

  const input = e.tool_input ? (typeof e.tool_input==='string' ? e.tool_input : JSON.stringify(e.tool_input,null,2))
    : e.content || ''
  const output = e.result ? (typeof e.result==='string' ? e.result : JSON.stringify(e.result,null,2)) : ''

  return (
    <>
      <div className="px-3 py-2 border-b border-white/[0.04] flex items-center justify-between flex-shrink-0">
        <div className="flex items-center gap-1.5">
          <span className="text-xxs font-mono text-t-quaternary">#{e._i+1}</span>
          <span className="text-sm font-medium text-t-primary">
            {e.type==='tool_call'?(e.tool_name||'Tool Call'):(e.type==='message'?e.role:e.type)}
          </span>
        </div>
        <button onClick={onClose} className="text-t-quaternary hover:text-t-secondary">
          <XCircle size={14}/>
        </button>
      </div>
      <div className="flex border-b border-white/[0.04] flex-shrink-0">
        {tabs.map(t=>(
          <button key={t} onClick={()=>setTab(t)}
            className={`flex-1 py-1.5 text-xxs uppercase tracking-wider font-medium transition-colors ${
              tab===t ? 'text-brand border-b border-brand' : 'text-t-quaternary hover:text-t-tertiary'
            }`}>
            {t}
          </button>
        ))}
      </div>
      <div className="flex-1 overflow-auto p-3">
        {tab==='input' && (
          <pre className="text-xxs text-t-secondary font-mono whitespace-pre-wrap break-words bg-app rounded p-2 border border-white/[0.04]">
            {input || '(empty)'}
          </pre>
        )}
        {tab==='output' && (
          <pre className="text-xxs text-t-secondary font-mono whitespace-pre-wrap break-words bg-app rounded p-2 border border-white/[0.04]">
            {output || '(empty)'}
          </pre>
        )}
        {tab==='metadata' && (
          <div className="space-y-2 text-xxs">
            <MR label="Type" value={e.type} />
            {e.role && <MR label="Role" value={e.role} />}
            {e.tool_name && <MR label="Tool" value={e.tool_name} />}
            {e.content_hash && <MR label="Hash" value={e.content_hash} mono />}
            {e.timestamp && <MR label="Time" value={e.timestamp} />}
          </div>
        )}
      </div>
    </>
  )
}

function MR({label,value,mono}) {
  return (
    <div className="flex items-start justify-between">
      <span className="text-t-quaternary">{label}</span>
      <span className={`text-t-secondary text-right max-w-[200px] break-all ${mono?'font-mono text-micro':''}`}>{value}</span>
    </div>
  )
}

/* ══════════ PROVENANCE ══════════ */
function ProvenanceTab({ data }) {
  const records = data.records || [], v = data.verification || {}
  const [show, setShow] = useState(50)
  const types = {}; records.forEach(r=>{types[r.type]=(types[r.type]||0)+1})

  return (
    <div className="space-y-3 max-w-5xl">
      <div className={`card p-3 flex items-center gap-2.5 ${v.valid?'':'border-danger/20'}`}>
        {v.valid ? <CheckCircle2 className="text-emerald-400" size={16}/> : <XCircle className="text-red-400" size={16}/>}
        <div>
          <div className={`text-sm font-medium ${v.valid?'text-emerald-400':'text-red-400'}`}>
            {v.valid ? 'SHA-256 Hash Chain Verified' : 'Chain Integrity Broken'}
          </div>
          <div className="text-xxs text-t-quaternary">{records.length} records · Merkle: {shortHash(v.merkle_root)}</div>
        </div>
      </div>
      <div className="grid grid-cols-5 gap-2">
        {Object.entries(types).map(([t,c])=>(
          <div key={t} className="card p-2 text-center">
            <div className="text-micro text-t-quaternary uppercase">{t}</div>
            <div className="text-sm font-semibold text-t-primary">{c}</div>
          </div>
        ))}
      </div>
      <div className="space-y-px">
        {records.slice(0,show).map((r,i)=>(
          <div key={i} className="card px-2.5 py-1.5 flex items-center gap-2 group tr-hover">
            <div className="w-5 h-5 rounded text-micro font-bold flex items-center justify-center bg-brand/15 text-brand flex-shrink-0">{r.sequence}</div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-1.5">
                <span className="text-xxs font-mono px-1 py-px bg-raised rounded text-t-tertiary">{r.type}</span>
                <span className="text-xs text-t-secondary truncate">{r.name}</span>
              </div>
              <div className="hash-text mt-px truncate">{r.hash}</div>
            </div>
            {i>0 && <div className="hidden group-hover:block text-micro text-t-quaternary font-mono flex-shrink-0">prev: {shortHash(r.previous_hash)}</div>}
          </div>
        ))}
      </div>
      {show<records.length && (
        <button onClick={()=>setShow(s=>s+100)} className="w-full py-1.5 text-xxs text-brand bg-raised/50 rounded">
          Show more ({records.length-show} remaining)
        </button>
      )}
    </div>
  )
}

/* ══════════ SECURITY ══════════ */
function SecurityTab({ data }) {
  const risk = data.risk||{}, patterns=risk.patterns||[], causal=risk.causal_chains||[]
  const ontSec=data.ontology?.security||{}, findings=ontSec.findings||[], inj=ontSec.prompt_injection||{}

  return (
    <div className="space-y-4 max-w-5xl">
      <div className="card p-4">
        <div className="flex items-center justify-between">
          <div className="section-label">Risk Assessment</div>
          <span className={`badge ${riskBadge(getRiskLevel(risk))}`}>{getRiskLevel(risk)}</span>
        </div>
        <div className="flex items-center gap-3 mt-2">
          <div className={`text-3xl font-black ${riskTextColor(risk.risk_score)}`}>
            {risk.risk_score??0}<span className="text-md text-t-quaternary">/100</span>
          </div>
          <div className="flex-1">
            <div className="h-1.5 bg-white/[0.04] rounded-full overflow-hidden">
              <div className="h-full rounded-full" style={{width:`${risk.risk_score||0}%`,background:riskColor(risk.risk_score)}} />
            </div>
            <div className="flex justify-between mt-0.5 text-micro text-t-quaternary">
              <span>Engine: {risk.engine||'graphrag'}</span><span>{patterns.length} patterns</span>
            </div>
          </div>
        </div>
      </div>

      {patterns.length>0 && (
        <div className="card p-4">
          <div className="section-label mb-2 flex items-center gap-1"><Zap size={11} className="text-warning"/> Patterns ({patterns.length})</div>
          <div className="space-y-1">
            {patterns.map((p,i)=><PatternRow key={i} p={p}/>)}
          </div>
        </div>
      )}

      {findings.length>0 && (
        <div className="card p-4">
          <div className="section-label mb-2">Ontology Findings ({findings.length})</div>
          <div className="space-y-1">
            {findings.map((f,i)=>(
              <div key={i} className={`p-2.5 rounded border ${sevBorder(f.severity)}`}>
                <div className="flex items-center justify-between mb-0.5">
                  <span className="text-sm font-medium text-t-primary">{f.title}</span>
                  <span className={`badge ${riskBadge(f.severity)}`}>{f.severity}</span>
                </div>
                <p className="text-xxs text-t-tertiary">{f.description}</p>
                {f.mitre && <div className="text-micro font-mono text-t-quaternary mt-0.5">{f.mitre}</div>}
              </div>
            ))}
          </div>
        </div>
      )}

      {(inj.graph_suspects||0)+(inj.session_suspects||0)>0 && (
        <div className="card p-4 border-danger/15">
          <div className="text-xs font-medium text-red-400 mb-2 flex items-center gap-1"><AlertTriangle size={12}/> Prompt Injection</div>
          <div className="grid grid-cols-2 gap-2 mb-2">
            <SC label="Graph Suspects" value={inj.graph_suspects||0} color="text-red-400"/>
            <SC label="Session Suspects" value={inj.session_suspects||0} color="text-red-400"/>
          </div>
        </div>
      )}

      {causal.length>0 && (
        <div className="card p-4">
          <div className="section-label mb-2">Causal Chains ({causal.length})</div>
          <div className="space-y-1">
            {causal.slice(0,10).map((c,i)=>(
              <div key={i} className={`p-2 rounded border ${c.is_risky?'border-warning/20 bg-warning/5':'border-white/[0.04]'}`}>
                <div className="flex items-center gap-1 flex-wrap">
                  {c.chain?.map((s,j)=>(
                    <span key={j} className="flex items-center gap-0.5">
                      <span className="text-xxs font-mono px-1 py-px bg-raised rounded text-t-tertiary">{s}</span>
                      {j<c.chain.length-1 && <span className="text-t-quaternary text-micro">→</span>}
                    </span>
                  ))}
                </div>
                {c.is_risky && <div className="text-xxs text-warning mt-0.5 flex items-center gap-0.5"><AlertTriangle size={9}/>{c.reason||'Risky'}</div>}
              </div>
            ))}
          </div>
        </div>
      )}

      {risk.mitre_mapping && Object.keys(risk.mitre_mapping).length>0 && (
        <div className="card p-4">
          <div className="section-label mb-2">MITRE ATT&CK</div>
          <div className="grid grid-cols-3 gap-1.5">
            {Object.entries(risk.mitre_mapping).map(([t,tech])=>(
              <div key={t} className="p-2 bg-raised rounded border border-white/[0.04]">
                <div className="text-xs font-medium text-t-primary">{t}</div>
                <div className="text-micro font-mono text-t-quaternary mt-0.5">{Array.isArray(tech)?tech.join(', '):tech}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function PatternRow({p}) {
  const [open,setOpen]=useState(false)
  return (
    <div className={`rounded border ${sevBorder(p.risk)}`}>
      <button onClick={()=>setOpen(!open)} className="w-full text-left p-2.5 flex items-center justify-between">
        <div className="flex items-center gap-1.5">
          <span className="text-xxs font-mono text-t-quaternary">{p.id}</span>
          <span className="text-sm font-medium text-t-primary">{p.name}</span>
        </div>
        <div className="flex items-center gap-1.5">
          {p.confidence && <span className="text-xxs text-t-quaternary">{Math.round(p.confidence*100)}%</span>}
          <span className={`badge ${riskBadge(p.risk)}`}>{p.risk}</span>
          {open?<ChevronDown size={11} className="text-t-quaternary"/>:<ChevronRight size={11} className="text-t-quaternary"/>}
        </div>
      </button>
      {open && (
        <div className="px-2.5 pb-2.5 border-t border-white/[0.04]">
          <p className="text-xxs text-t-tertiary mt-1.5">{p.description}</p>
          {p.mitre_tactic && <div className="text-micro font-mono text-t-quaternary mt-0.5">MITRE: {p.mitre_tactic}</div>}
        </div>
      )}
    </div>
  )
}

/* ══════════ DATA FLOWS (Palantir Lineage style) ══════════ */
function DataFlowsTab({ data }) {
  const canvasRef=useRef(null), posRef=useRef({}), dragRef=useRef(null)
  const panRef=useRef({x:0,y:0}), lastMouse=useRef({x:0,y:0}), isPanning=useRef(false), scaleRef=useRef(1)
  const [selectedNode, setSelectedNode]=useState(null)
  const nodes=data.ontology?.vis_nodes||[], edges=data.ontology?.vis_edges||[]

  const COLORS = {
    Agent:'#6366f1', Session:'#8b5cf6', ToolCall:'#3b82f6',
    Entity:'#10b981', Decision:'#f59e0b', Risk:'#ef4444', Policy:'#64748b',
    Prompt:'#ec4899', Response:'#06b6d4',
  }

  const initPos=useCallback(()=>{
    if(!nodes.length) return
    const w=canvasRef.current?.width||800, h=canvasRef.current?.height||600
    const cx=w/2,cy=h/2, groups={}
    nodes.forEach(n=>{if(!groups[n.class]) groups[n.class]=[]; groups[n.class].push(n)})
    const cls=Object.keys(groups), pos={}
    cls.forEach((c,gi)=>{
      const a0=(2*Math.PI*gi)/cls.length-Math.PI/2, rR=Math.min(w,h)*0.3
      const gcx=cx+Math.cos(a0)*rR, gcy=cy+Math.sin(a0)*rR
      groups[c].forEach((n,ni)=>{
        const a=(2*Math.PI*ni)/groups[c].length, r=Math.min(40+groups[c].length*3,120)
        pos[n.id]={x:gcx+Math.cos(a)*r+(Math.random()-0.5)*20, y:gcy+Math.sin(a)*r+(Math.random()-0.5)*20, vx:0,vy:0}
      })
    })
    posRef.current=pos
  },[nodes])

  const draw=useCallback(()=>{
    const cv=canvasRef.current; if(!cv) return
    const ctx=cv.getContext('2d'), pos=posRef.current, pan=panRef.current, sc=scaleRef.current
    ctx.clearRect(0,0,cv.width,cv.height); ctx.save(); ctx.translate(pan.x,pan.y); ctx.scale(sc,sc)
    for(const e of edges){
      const s=pos[e.s],t=pos[e.t]; if(!s||!t) continue
      const hl=selectedNode&&(e.s===selectedNode.id||e.t===selectedNode.id)
      ctx.strokeStyle=hl?'rgba(99,102,241,0.5)':'rgba(110,118,129,0.12)'
      ctx.lineWidth=hl?1.5:0.5; ctx.beginPath(); ctx.moveTo(s.x,s.y); ctx.lineTo(t.x,t.y); ctx.stroke()
    }
    for(const n of nodes){
      const p=pos[n.id]; if(!p) continue
      const col=COLORS[n.class]||'#6e7681', sel=selectedNode?.id===n.id
      const r=n.class==='Agent'||n.class==='Session'?8:n.class==='Entity'?6:4
      if(sel){ctx.beginPath();ctx.arc(p.x,p.y,r+4,0,Math.PI*2);ctx.fillStyle=col+'30';ctx.fill()}
      ctx.beginPath();ctx.arc(p.x,p.y,r,0,Math.PI*2);ctx.fillStyle=sel?'#e6edf3':col;ctx.fill()
      if(n.class!=='ToolCall'||sel){
        ctx.font=`${sel?'bold ':''}9px Inter,sans-serif`
        ctx.fillStyle=sel?'#e6edf3':'#6e7681'; ctx.textAlign='center'
        ctx.fillText(n.label||n.id.substring(0,12),p.x,p.y-r-4)
      }
    }
    ctx.restore()
  },[nodes,edges,selectedNode])

  const simulate=useCallback(()=>{
    const pos=posRef.current, ids=Object.keys(pos); if(!ids.length) return
    for(let it=0;it<50;it++){
      for(let i=0;i<ids.length;i++) for(let j=i+1;j<ids.length;j++){
        const a=pos[ids[i]],b=pos[ids[j]]; const dx=b.x-a.x,dy=b.y-a.y,d2=dx*dx+dy*dy+1,f=800/d2
        a.vx-=dx*f;a.vy-=dy*f;b.vx+=dx*f;b.vy+=dy*f
      }
      for(const e of edges){
        const a=pos[e.s],b=pos[e.t]; if(!a||!b) continue
        const dx=b.x-a.x,dy=b.y-a.y,d=Math.sqrt(dx*dx+dy*dy)+.1,f=(d-60)*0.01
        a.vx+=(dx/d)*f;a.vy+=(dy/d)*f;b.vx-=(dx/d)*f;b.vy-=(dy/d)*f
      }
      for(const id of ids){const p=pos[id];p.vx*=0.8;p.vy*=0.8;p.x+=p.vx;p.y+=p.vy}
    }
  },[edges])

  useEffect(()=>{
    const cv=canvasRef.current; if(!cv) return
    cv.width=cv.parentElement.clientWidth; cv.height=500
    panRef.current={x:0,y:0}; scaleRef.current=1
    initPos(); simulate(); draw()
  },[initPos,simulate,draw])

  const findNode=(mx,my)=>{for(const n of nodes){const p=posRef.current[n.id];if(!p)continue;const dx=mx-p.x,dy=my-p.y;if(dx*dx+dy*dy<100)return n}return null}
  const onDown=e=>{const r=canvasRef.current.getBoundingClientRect(),mx=(e.clientX-r.left-panRef.current.x)/scaleRef.current,my=(e.clientY-r.top-panRef.current.y)/scaleRef.current;const n=findNode(mx,my);if(n){dragRef.current=n.id;setSelectedNode(n);return};isPanning.current=true;lastMouse.current={x:e.clientX,y:e.clientY}}
  const onMove=e=>{if(dragRef.current){const r=canvasRef.current.getBoundingClientRect();posRef.current[dragRef.current].x=(e.clientX-r.left-panRef.current.x)/scaleRef.current;posRef.current[dragRef.current].y=(e.clientY-r.top-panRef.current.y)/scaleRef.current;draw()}else if(isPanning.current){panRef.current.x+=e.clientX-lastMouse.current.x;panRef.current.y+=e.clientY-lastMouse.current.y;lastMouse.current={x:e.clientX,y:e.clientY};draw()}}
  const onUp=()=>{dragRef.current=null;isPanning.current=false}
  const onWheel=e=>{e.preventDefault();scaleRef.current=Math.max(0.2,Math.min(3,scaleRef.current*(e.deltaY>0?0.9:1.1)));draw()}

  if(!nodes.length) return <div className="card p-10 text-center text-xs text-t-quaternary">No graph data available</div>

  const connEdges=selectedNode?edges.filter(e=>e.s===selectedNode.id||e.t===selectedNode.id):[]

  return (
    <div className="space-y-2 max-w-full">
      <div className="flex items-center justify-between">
        <div className="text-xxs text-t-quaternary">{nodes.length} nodes · {edges.length} edges</div>
        <div className="flex gap-2 flex-wrap">
          {Object.entries(COLORS).map(([c,col])=>(
            <span key={c} className="text-micro text-t-quaternary flex items-center gap-0.5">
              <span className="w-2 h-2 rounded-full" style={{background:col}}/>{c}
            </span>
          ))}
        </div>
      </div>
      <div className="flex gap-2.5">
        <div className="card overflow-hidden flex-1">
          <canvas ref={canvasRef} className="kg-canvas w-full"
            onMouseDown={onDown} onMouseMove={onMove} onMouseUp={onUp} onMouseLeave={onUp} onWheel={onWheel}/>
        </div>
        {selectedNode && (
          <div className="card p-3 w-64 flex-shrink-0 space-y-2.5">
            <div className="flex items-center justify-between">
              <span className="text-xxs font-mono px-1.5 py-0.5 rounded" style={{background:(COLORS[selectedNode.class]||'#64748b')+'25',color:COLORS[selectedNode.class]||'#6e7681'}}>{selectedNode.class}</span>
              <button onClick={()=>setSelectedNode(null)} className="text-t-quaternary hover:text-t-secondary"><XCircle size={13}/></button>
            </div>
            <div className="text-xs text-t-primary font-medium break-all">{selectedNode.label||selectedNode.id}</div>
            <div className="hash-text break-all">{selectedNode.id}</div>
            {selectedNode.ts && <div className="text-xxs text-t-quaternary flex items-center gap-1"><Clock size={10}/>{selectedNode.ts}</div>}
            {selectedNode.attrs&&Object.keys(selectedNode.attrs).length>0 && (
              <div className="space-y-1 pt-1 border-t border-white/[0.04]">
                <div className="section-label">Attributes</div>
                {Object.entries(selectedNode.attrs).map(([k,v])=>(
                  <div key={k} className="flex items-center justify-between text-xxs">
                    <span className="text-t-quaternary">{k}</span>
                    <span className="text-t-secondary font-mono">{typeof v==='string'?v.substring(0,25):JSON.stringify(v)}</span>
                  </div>
                ))}
              </div>
            )}
            {connEdges.length>0 && (
              <div className="space-y-1 pt-1 border-t border-white/[0.04]">
                <div className="section-label">Connections ({connEdges.length})</div>
                {connEdges.slice(0,6).map((e,i)=>(
                  <div key={i} className="text-xxs text-t-quaternary font-mono truncate">
                    {e.s===selectedNode.id?'→':'←'} {e.r} {e.s===selectedNode.id?e.t:e.s}
                  </div>
                ))}
                {connEdges.length>6 && <div className="text-micro text-t-quaternary">+{connEdges.length-6} more</div>}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

/* ══════════ GOVERNANCE ══════════ */
function GovernanceTab({ data }) {
  const compliance=data.compliance||{}, owasp=data.owasp||{}, drift=data.drift||{}
  const permissions=data.permissions||{}, cost=data.cost||{}, topology=data.topology||{}

  return (
    <div className="space-y-4 max-w-5xl">
      {/* EU AI Act */}
      <div className="card overflow-hidden">
        <div className="px-3 py-2 border-b border-white/[0.04] flex items-center gap-1">
          <Scale size={11} className="text-accent-violet"/> <span className="section-label">EU AI Act Compliance</span>
        </div>
        {compliance.checks?.length > 0 ? (
          <table className="w-full"><thead><tr>
            <th className="th">Check</th><th className="th">Article</th><th className="th">Description</th><th className="th text-right">Status</th>
          </tr></thead><tbody>
            {compliance.checks.map((c,i)=>(
              <tr key={i}><td className="td text-xs text-t-primary font-medium">{c.name||c.check_id}</td>
              <td className="td text-xs font-mono text-t-quaternary">{c.article||'-'}</td>
              <td className="td text-xxs text-t-tertiary">{c.description||'-'}</td>
              <td className="td text-right"><span className={`badge ${statusBadge(c.status)}`}>{c.status}</span></td></tr>
            ))}
          </tbody></table>
        ) : <div className="p-4 text-xxs text-t-quaternary">No compliance data</div>}
      </div>

      {/* OWASP */}
      <div className="card overflow-hidden">
        <div className="px-3 py-2 border-b border-white/[0.04] flex items-center gap-1">
          <Shield size={11} className="text-info"/> <span className="section-label">OWASP LLM Top 10</span>
        </div>
        {getOwaspItems(owasp).length > 0 ? (
          <table className="w-full"><thead><tr>
            <th className="th">ID</th><th className="th">Name</th><th className="th">Description</th><th className="th text-right">Status</th>
          </tr></thead><tbody>
            {getOwaspItems(owasp).map((it,i)=>(
              <tr key={i}><td className="td text-xs font-mono text-t-quaternary">{it.id}</td>
              <td className="td text-xs text-t-primary font-medium">{it.name}</td>
              <td className="td text-xxs text-t-tertiary max-w-xs truncate">{it.description}</td>
              <td className="td text-right"><span className={`badge ${statusBadge(it.status)}`}>{it.status}</span></td></tr>
            ))}
          </tbody></table>
        ) : <div className="p-4 text-xxs text-t-quaternary">No OWASP data</div>}
      </div>

      {/* Drift */}
      <div className="card p-4">
        <div className="section-label mb-2 flex items-center gap-1"><Activity size={11} className="text-warning"/> Behavioral Drift</div>
        {drift.drift_detected!==undefined && (
          <div className="flex items-center gap-2 mb-2">
            <span className={`text-md font-bold ${drift.drift_detected?'text-warning':'text-emerald-400'}`}>
              {drift.drift_detected?'DRIFT':'NORMAL'}
            </span>
            <span className="text-xxs text-t-quaternary">score: {drift.drift_score??0}</span>
          </div>
        )}
        {getDriftAnomalies(drift).length > 0 ? (
          <div className="space-y-1">
            {getDriftAnomalies(drift).map((a,i)=>(
              <div key={i} className="p-2 bg-warning/5 rounded border border-warning/15 flex items-center justify-between">
                <div><div className="text-xs font-medium text-warning">{a.tool||a.metric}</div>
                <div className="text-xxs text-warning/60">{a.description||`z-score: ${a.z_score?.toFixed(2)}`}</div></div>
                {a.z_score && <span className="text-xs font-mono text-warning">z={a.z_score.toFixed(2)}</span>}
              </div>
            ))}
          </div>
        ) : <div className="text-xs text-emerald-400 flex items-center gap-1"><CheckCircle2 size={12}/> No anomalies</div>}
      </div>

      {/* Permissions */}
      {permissions.agents && Object.keys(permissions.agents).length>0 && (
        <div className="card p-4">
          <div className="section-label mb-2 flex items-center gap-1"><Lock size={11} className="text-risk-high"/> Permissions</div>
          {Object.entries(permissions.agents).map(([a,perms])=>(
            <div key={a} className="mb-2">
              <div className="text-xs font-medium text-t-primary font-mono mb-1">{a}</div>
              <div className="flex flex-wrap gap-0.5">
                {Object.entries(perms).map(([t,p])=>(
                  <span key={t} className={`text-micro px-1 py-px rounded font-mono ${
                    p==='allow'?'bg-success/15 text-success':p==='deny'?'bg-danger/15 text-danger':'bg-warning/15 text-warning'}`}>
                    {t}:{p}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Cost */}
      {cost && (cost.total_cost>0 || (cost.by_model&&Object.keys(cost.by_model).length>0)) && (
        <div className="card p-4">
          <div className="section-label mb-2 flex items-center gap-1"><DollarSign size={11} className="text-success"/> Cost</div>
          {cost.total_cost>0 && <div className="text-lg font-bold text-success mb-2">${cost.total_cost.toFixed(4)}</div>}
          {cost.by_model && Object.entries(cost.by_model).map(([m,mc])=>(
            <div key={m} className="flex items-center justify-between text-xxs p-1.5 bg-raised rounded mb-0.5">
              <span className="text-t-secondary font-mono">{m}</span>
              <span className="text-success">${mc.cost?.toFixed(4)||'0'} <span className="text-t-quaternary">({mc.input_tokens||0}in/{mc.output_tokens||0}out)</span></span>
            </div>
          ))}
        </div>
      )}

      {/* Topology */}
      {topology.nodes?.length>0 && (
        <div className="card p-4">
          <div className="section-label mb-2 flex items-center gap-1"><GitBranch size={11} className="text-blue-400"/> Topology</div>
          <div className="grid grid-cols-2 gap-2">
            <div><div className="section-label mb-1">Nodes ({topology.nodes.length})</div>
              {topology.nodes.map((n,i)=><div key={i} className="text-xxs text-t-secondary p-1 bg-raised rounded mb-0.5 font-mono">{n.id||n}</div>)}</div>
            <div><div className="section-label mb-1">Edges ({topology.edges?.length||0})</div>
              {(topology.edges||[]).map((e,i)=><div key={i} className="text-xxs text-t-tertiary p-1 bg-raised rounded mb-0.5 font-mono">{e.source||e.from}→{e.target||e.to}</div>)}</div>
          </div>
        </div>
      )}
    </div>
  )
}

/* ══════════ AI ANALYSIS ══════════ */
function AIAnalysisTab({ data }) {
  const [apiKey,setApiKey]=useState(''), [provider,setProvider]=useState('openai')
  const [analyzing,setAnalyzing]=useState(false), [result,setResult]=useState(null), [error,setError]=useState(null)

  const analyze=async()=>{
    if(!apiKey)return; setAnalyzing(true); setError(null)
    try {
      const s=JSON.stringify({session_id:data.session_id,risk:data.risk,records_count:data.records?.length,
        patterns:data.risk?.patterns?.map(p=>({id:p.id,name:p.name,risk:p.risk})),
        findings:data.ontology?.security?.findings?.map(f=>({title:f.title,severity:f.severity}))})
      const r=await analyzeSession(apiKey,s,provider); setResult(r.result)
    } catch(e){setError(e.message)} finally{setAnalyzing(false)}
  }

  return (
    <div className="space-y-4 max-w-3xl">
      <div className="card p-4">
        <div className="section-label mb-2 flex items-center gap-1"><Brain size={11} className="text-accent-violet"/> AI Security Analysis</div>
        <p className="text-xxs text-t-quaternary mb-3">Your API key goes directly to the provider. Zero telemetry.</p>
        <div className="space-y-2.5">
          <div>
            <div className="section-label mb-1">Provider</div>
            <div className="flex gap-1.5">
              {['openai','anthropic'].map(p=>(
                <button key={p} onClick={()=>setProvider(p)}
                  className={`px-2.5 py-1 rounded text-xxs font-medium ${
                    provider===p?'bg-brand/15 text-brand ring-1 ring-brand/25':'bg-raised text-t-quaternary hover:text-t-tertiary'}`}>
                  {p==='openai'?'OpenAI':'Anthropic'}
                </button>
              ))}
            </div>
          </div>
          <div>
            <div className="section-label mb-1">API Key</div>
            <input type="password" value={apiKey} onChange={e=>setApiKey(e.target.value)}
              placeholder={provider==='openai'?'sk-…':'sk-ant-…'} className="input w-full"/>
          </div>
          <button onClick={analyze} disabled={analyzing||!apiKey}
            className="btn-primary disabled:opacity-40"><Send size={12}/>{analyzing?'Analyzing…':'Analyze'}</button>
        </div>
      </div>
      <div className="card p-2.5 flex items-center gap-1.5">
        <Lock size={11} className="text-success"/><span className="text-xxs text-t-quaternary">Zero-trust: API calls go directly from your browser.</span>
      </div>
      {error && <div className="card p-3"><p className="text-xs text-danger">{error}</p></div>}
      {result && <div className="card p-4"><div className="section-label mb-2">Result</div>
        <pre className="text-xxs text-t-secondary font-mono whitespace-pre-wrap bg-app rounded p-3 border border-white/[0.04] overflow-auto max-h-96">{result}</pre></div>}
    </div>
  )
}

/* ══════════ SHARED ══════════ */
function SC({label,value,color,mono}) {
  return (
    <div className="card p-2.5">
      <div className="section-label">{label}</div>
      <div className={`text-md font-semibold mt-0.5 ${color||'text-t-primary'} ${mono?'font-mono text-xxs':''}`}>{value}</div>
    </div>
  )
}
function QS({label,val}) {
  return <div className="flex items-center justify-between"><span className="text-xs text-t-tertiary">{label}</span>
    <span className="text-sm font-semibold text-t-primary">{typeof val==='number'?val.toLocaleString():val}</span></div>
}
function sevBorder(s) {
  const l=(s||'').toLowerCase()
  if(l==='critical') return 'bg-danger/5 border-danger/15'
  if(l==='high') return 'bg-risk-high/5 border-risk-high/15'
  if(l==='medium'||l==='warn') return 'bg-warning/5 border-warning/15'
  return 'bg-white/[0.01] border-white/[0.06]'
}
