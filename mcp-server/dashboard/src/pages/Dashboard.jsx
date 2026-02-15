import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Shield, Activity, AlertTriangle, CheckCircle2, XCircle,
  ArrowRight, Download, Hash, Zap, TrendingUp, Database,
} from 'lucide-react'
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts'
import { Network } from 'lucide-react'
import {
  fetchLatestSession, fetchSessions, fetchOntologyExport, riskBadge, formatTime,
  shortHash, getRiskLevel, getOwaspItems, riskColor, riskTextColor,
  downloadJSON, downloadCSV, downloadOntology,
} from '../api'

const PIE_COLORS = ['#6366f1', '#8b5cf6', '#a855f7', '#06b6d4', '#10b981', '#f59e0b', '#ef4444']

export default function Dashboard() {
  const [data, setData] = useState(null)
  const [sessions, setSessions] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const navigate = useNavigate()

  useEffect(() => {
    Promise.all([fetchLatestSession(), fetchSessions()])
      .then(([d, s]) => { setData(d); setSessions(s.sessions || []) })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <Loader />
  if (error) return <Err msg={error} />
  if (!data) return <Err msg="No data" />

  const risk = data.risk || {}
  const v = data.verification || {}
  const ont = data.ontology || {}
  const owasp = data.owasp || {}
  const owaspItems = getOwaspItems(owasp)
  const compliance = data.compliance || {}
  const drift = data.drift || {}
  const patterns = (risk.patterns || []).slice(0, 6)

  const typeCounts = {}
  for (const r of (data.records || [])) typeCounts[r.type] = (typeCounts[r.type] || 0) + 1
  const typeData = Object.entries(typeCounts).map(([name, value]) => ({ name, value }))

  return (
    <div className="p-5 max-w-7xl mx-auto space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between animate-in">
        <div>
          <h1 className="text-xl font-semibold text-t-primary">Overview</h1>
          <p className="text-xxs text-t-quaternary font-mono mt-0.5">{data.session_id}</p>
        </div>
        <div className="flex items-center gap-1.5">
          <button onClick={() => downloadJSON(data)} className="btn-ghost">
            <Download size={11} /> JSON
          </button>
          <button onClick={() => downloadCSV(data.records)} className="btn-ghost">
            <Download size={11} /> CSV
          </button>
          <button onClick={() => fetchOntologyExport(data.session_id).then(downloadOntology).catch(e => alert(e.message))} className="btn-ghost">
            <Network size={11} /> Ontology
          </button>
        </div>
      </div>

      {/* Metric cards */}
      <div className="grid grid-cols-5 gap-2.5">
        <MetricCard label="Risk Score" value={risk.risk_score ?? 0} suffix="/100"
          color={riskTextColor(risk.risk_score)}
          badge={<span className={`badge ${riskBadge(getRiskLevel(risk))}`}>{getRiskLevel(risk)}</span>} />
        <MetricCard label="Chain Integrity"
          value={v.valid ? 'VERIFIED' : 'BROKEN'}
          color={v.valid ? 'text-emerald-400' : 'text-red-400'}
          sub={`${data.records?.length || 0} records`} />
        <MetricCard label="OWASP Score"
          value={`${owasp.overall_score ?? owaspItems.filter(i => i.status === 'PASS').length}/${owaspItems.length || 10}`}
          color="text-info"
          badge={<span className={`badge ${owasp.overall_status === 'FAIL' ? 'badge-fail' : 'badge-pass'}`}>
            {owasp.overall_status || 'PASS'}
          </span>} />
        <MetricCard label="Compliance"
          value={`${compliance.checks?.length || 0} checks`}
          color="text-accent-violet"
          badge={<span className={`badge ${compliance.overall_status === 'FAIL' ? 'badge-fail' : compliance.overall_status === 'PARTIAL' ? 'badge-warn' : 'badge-pass'}`}>
            {compliance.overall_status || 'PASS'}
          </span>} />
        <MetricCard label="Drift"
          value={drift.drift_detected ? 'DETECTED' : 'NORMAL'}
          color={drift.drift_detected ? 'text-warning' : 'text-emerald-400'}
          sub={`score: ${drift.drift_score ?? 0}`} />
      </div>

      {/* Middle row */}
      <div className="grid grid-cols-3 gap-2.5">
        {/* Risk gauge */}
        <div className="card p-4 animate-in delay-1">
          <div className="section-label mb-3">Risk Analysis</div>
          <div className="flex items-center justify-center">
            <div className="relative w-28 h-28">
              <svg viewBox="0 0 120 120" className="w-full h-full">
                <circle cx="60" cy="60" r="48" fill="none" stroke="rgba(255,255,255,0.04)" strokeWidth="7" />
                <circle cx="60" cy="60" r="48" fill="none"
                  stroke={riskColor(risk.risk_score)}
                  strokeWidth="7" strokeDasharray={`${(risk.risk_score || 0) * 3.01} 301`}
                  strokeLinecap="round" transform="rotate(-90 60 60)"
                  style={{ filter: `drop-shadow(0 0 6px ${riskColor(risk.risk_score)}40)` }} />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className={`text-2xl font-black ${riskTextColor(risk.risk_score)}`}>
                  {risk.risk_score ?? 0}
                </span>
                <span className="text-micro text-t-quaternary">/100</span>
              </div>
            </div>
          </div>
          <div className="text-center mt-1.5">
            <span className="text-xxs text-t-quaternary">
              {patterns.length} patterns · {risk.engine || 'graphrag'}
            </span>
          </div>
        </div>

        {/* Event distribution */}
        <div className="card p-4 animate-in delay-2">
          <div className="section-label mb-2">Event Distribution</div>
          {typeData.length > 0 ? (
            <>
              <ResponsiveContainer width="100%" height={130}>
                <PieChart>
                  <Pie data={typeData} dataKey="value" nameKey="name" cx="50%" cy="50%"
                    outerRadius={50} innerRadius={25} paddingAngle={2} strokeWidth={0}>
                    {typeData.map((_, i) => <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />)}
                  </Pie>
                  <Tooltip contentStyle={{
                    background: '#1c2333', border: '1px solid rgba(255,255,255,0.08)',
                    borderRadius: '6px', fontSize: '11px', color: '#8b949e',
                  }} />
                </PieChart>
              </ResponsiveContainer>
              <div className="flex flex-wrap gap-x-2.5 gap-y-0.5 justify-center">
                {typeData.map((d, i) => (
                  <span key={d.name} className="text-xxs text-t-quaternary flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-full" style={{ background: PIE_COLORS[i % PIE_COLORS.length] }} />
                    {d.name}
                  </span>
                ))}
              </div>
            </>
          ) : <div className="h-36 flex items-center justify-center text-xxs text-t-quaternary">No events</div>}
        </div>

        {/* Quick stats */}
        <div className="card p-4 space-y-2.5 animate-in delay-3">
          <div className="section-label">Quick Stats</div>
          <QS label="Sessions" value={sessions.length} icon={Database} />
          <QS label="Events (latest)" value={data.session_log?.length || 0} icon={Activity} />
          <QS label="KG Nodes" value={ont.total_nodes || 0} />
          <QS label="KG Edges" value={ont.total_edges || 0} />
          <QS label="Entities" value={ont.data_flow?.entities_created || 0} />
        </div>
      </div>

      {/* Findings */}
      {patterns.length > 0 && (
        <div className="card p-4 animate-in delay-4">
          <div className="section-label mb-2.5 flex items-center gap-1">
            <Zap size={11} className="text-warning" /> Active Findings ({risk.patterns?.length || 0})
          </div>
          <div className="grid grid-cols-3 gap-2">
            {patterns.map((p, i) => (
              <div key={i} className="p-2.5 rounded-md bg-app border border-white/[0.04] hover:border-white/[0.1] transition-colors cursor-pointer"
                onClick={() => navigate(`/sessions/${data.session_id}`)}>
                <div className="flex items-center justify-between mb-0.5">
                  <span className="text-xxs font-mono text-t-quaternary">{p.id}</span>
                  <span className={`badge ${riskBadge(p.risk)}`}>{p.risk}</span>
                </div>
                <div className="text-sm text-t-primary font-medium leading-tight">{p.name}</div>
                <div className="text-xxs text-t-quaternary mt-0.5 line-clamp-2">{p.description}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Merkle + Recent sessions */}
      <div className="card p-3 flex items-center gap-2.5">
        <Hash size={13} className="text-brand flex-shrink-0" />
        <div className="flex-1 min-w-0">
          <div className="section-label">Merkle Root</div>
          <div className="hash-text truncate mt-0.5">{v.merkle_root || 'N/A'}</div>
        </div>
      </div>

      <div className="card overflow-hidden">
        <div className="flex items-center justify-between px-4 pt-3 pb-2">
          <div className="section-label">Recent Sessions</div>
          <button onClick={() => navigate('/sessions')}
            className="text-xxs text-brand hover:text-accent-indigo flex items-center gap-0.5">
            All <ArrowRight size={10} />
          </button>
        </div>
        <table className="w-full">
          <thead><tr>
            <th className="th">ID</th><th className="th">Time</th>
            <th className="th">Records</th><th className="th">Risk</th>
          </tr></thead>
          <tbody>
            {sessions.slice(0, 6).map(s => (
              <tr key={s.session_id} className="tr-hover"
                onClick={() => navigate(`/sessions/${s.session_id}`)}>
                <td className="td font-mono text-xs text-brand">{s.session_id.substring(0, 8)}</td>
                <td className="td text-xs">{formatTime(s.timestamp)}</td>
                <td className="td text-xs">{s.record_count || '-'}</td>
                <td className="td">
                  {s.risk_score != null ? (
                    <span className={`text-xs font-semibold ${riskTextColor(s.risk_score)}`}>{s.risk_score}</span>
                  ) : <span className="text-t-quaternary text-xxs">—</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function MetricCard({ label, value, suffix, color, badge, sub }) {
  return (
    <div className="card-hover p-3 animate-in">
      <div className="section-label">{label}</div>
      <div className={`text-lg font-bold mt-0.5 ${color || 'text-t-primary'}`}>
        {value}{suffix && <span className="text-xs text-t-quaternary">{suffix}</span>}
      </div>
      {badge && <div className="mt-0.5">{badge}</div>}
      {sub && <div className="text-xxs text-t-quaternary mt-0.5">{sub}</div>}
    </div>
  )
}

function QS({ label, value, icon: Icon }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-xs text-t-tertiary flex items-center gap-1">
        {Icon && <Icon size={11} />} {label}
      </span>
      <span className="text-sm font-semibold text-t-primary">
        {typeof value === 'number' ? value.toLocaleString() : value}
      </span>
    </div>
  )
}

function Loader() {
  return (
    <div className="flex items-center justify-center h-full">
      <div className="w-5 h-5 border-2 border-brand border-t-transparent rounded-full animate-spin" />
    </div>
  )
}

function Err({ msg }) {
  return (
    <div className="flex items-center justify-center h-full">
      <div className="card p-6 text-center">
        <XCircle size={28} className="text-danger/40 mx-auto mb-2" />
        <p className="text-xs text-t-tertiary">{msg}</p>
      </div>
    </div>
  )
}
