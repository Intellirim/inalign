import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Shield, Activity, AlertTriangle, CheckCircle2, XCircle,
  ArrowRight, Hash, Zap, TrendingUp, Database, HardDrive, Clock,
} from 'lucide-react'
import { fetchSessions, riskBadge, formatTime, riskColor, riskTextColor } from '../api'

export default function Dashboard() {
  const [sessions, setSessions] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const navigate = useNavigate()

  useEffect(() => {
    fetchSessions()
      .then(d => setSessions(d.sessions || []))
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <Loader />
  if (error) return <Err msg={error} />
  if (!sessions.length) return <Err msg="No sessions found" />

  const totalRecords = sessions.reduce((s, x) => s + (x.record_count || 0), 0)
  const totalSize = sessions.reduce((s, x) => s + (x.file_size_kb || 0), 0)
  const withRisk = sessions.filter(s => s.risk_score != null)
  const criticalCount = withRisk.filter(s => s.risk_score >= 75).length
  const verifiedCount = sessions.filter(s => s.chain_valid === true).length
  const avgScore = withRisk.length > 0
    ? Math.round(withRisk.reduce((s, r) => s + r.risk_score, 0) / withRisk.length)
    : 0

  return (
    <div className="p-5 max-w-7xl mx-auto space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between animate-in">
        <div>
          <h1 className="text-xl font-semibold text-t-primary">Overview</h1>
          <p className="text-xxs text-t-quaternary mt-0.5">
            {sessions.length} sessions · {totalRecords.toLocaleString()} records
          </p>
        </div>
      </div>

      {/* Metric cards */}
      <div className="grid grid-cols-5 gap-2.5">
        <MetricCard label="Sessions" value={sessions.length} icon={Database} />
        <MetricCard label="Total Records" value={totalRecords.toLocaleString()} icon={Activity} />
        <MetricCard label="Avg Risk" value={avgScore} suffix="/100"
          color={riskTextColor(avgScore)} icon={TrendingUp} />
        <MetricCard label="Critical" value={criticalCount} suffix=" sessions"
          color="text-danger" icon={AlertTriangle} />
        <MetricCard label="Verified" value={`${verifiedCount}/${sessions.length}`}
          color="text-emerald-400" icon={CheckCircle2} />
      </div>

      {/* Middle row */}
      <div className="grid grid-cols-3 gap-2.5">
        {/* Risk gauge */}
        <div className="card p-4 animate-in delay-1">
          <div className="section-label mb-3">Avg Risk Score</div>
          <div className="flex items-center justify-center">
            <div className="relative w-28 h-28">
              <svg viewBox="0 0 120 120" className="w-full h-full">
                <circle cx="60" cy="60" r="48" fill="none" stroke="rgba(255,255,255,0.04)" strokeWidth="7" />
                <circle cx="60" cy="60" r="48" fill="none"
                  stroke={riskColor(avgScore)}
                  strokeWidth="7" strokeDasharray={`${(avgScore || 0) * 3.01} 301`}
                  strokeLinecap="round" transform="rotate(-90 60 60)"
                  style={{ filter: `drop-shadow(0 0 6px ${riskColor(avgScore)}40)` }} />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className={`text-2xl font-black ${riskTextColor(avgScore)}`}>
                  {avgScore}
                </span>
                <span className="text-micro text-t-quaternary">/100</span>
              </div>
            </div>
          </div>
          <div className="text-center mt-1.5">
            <span className="text-xxs text-t-quaternary">
              {withRisk.length} analyzed · graphrag engine
            </span>
          </div>
        </div>

        {/* Risk distribution */}
        <div className="card p-4 animate-in delay-2">
          <div className="section-label mb-3">Risk Distribution</div>
          <div className="space-y-2">
            {[
              { label: 'Critical', min: 75, max: 100, color: 'bg-red-500' },
              { label: 'High', min: 50, max: 74, color: 'bg-orange-500' },
              { label: 'Medium', min: 25, max: 49, color: 'bg-amber-500' },
              { label: 'Low', min: 0, max: 24, color: 'bg-emerald-500' },
            ].map(tier => {
              const count = withRisk.filter(s => s.risk_score >= tier.min && s.risk_score <= tier.max).length
              const pct = withRisk.length > 0 ? (count / withRisk.length * 100) : 0
              return (
                <div key={tier.label} className="flex items-center gap-2">
                  <span className="text-xxs text-t-quaternary w-14">{tier.label}</span>
                  <div className="flex-1 h-1.5 bg-white/[0.04] rounded-full overflow-hidden">
                    <div className={`h-full rounded-full ${tier.color}`} style={{ width: `${pct}%` }} />
                  </div>
                  <span className="text-xxs text-t-tertiary w-6 text-right">{count}</span>
                </div>
              )
            })}
          </div>
          <div className="text-center mt-3">
            <span className="text-micro text-t-quaternary">
              {sessions.length - withRisk.length} not yet analyzed
            </span>
          </div>
        </div>

        {/* Quick stats */}
        <div className="card p-4 space-y-2.5 animate-in delay-3">
          <div className="section-label">Quick Stats</div>
          <QS label="Sessions" value={sessions.length} icon={Database} />
          <QS label="Total Records" value={totalRecords} icon={Activity} />
          <QS label="Storage" value={totalSize > 1024 ? `${(totalSize/1024).toFixed(1)} MB` : `${Math.round(totalSize)} KB`} icon={HardDrive} />
          <QS label="Analyzed" value={withRisk.length} icon={Shield} />
          <QS label="Verified Chains" value={verifiedCount} icon={CheckCircle2} />
        </div>
      </div>

      {/* Recent sessions table */}
      <div className="card overflow-hidden animate-in delay-4">
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
            <th className="th text-center">Chain</th>
          </tr></thead>
          <tbody>
            {sessions.slice(0, 8).map(s => (
              <tr key={s.session_id} className="tr-hover"
                onClick={() => navigate(`/sessions/${s.session_id}`)}>
                <td className="td font-mono text-xs text-brand">{s.session_id.substring(0, 8)}</td>
                <td className="td text-xs">{formatTime(s.timestamp)}</td>
                <td className="td text-xs">{s.record_count || '-'}</td>
                <td className="td">
                  {s.risk_score != null ? (
                    <div className="flex items-center gap-1.5">
                      <div className="w-12 h-1 bg-white/[0.04] rounded-full overflow-hidden">
                        <div className="h-full rounded-full" style={{
                          width: `${s.risk_score}%`,
                          background: riskColor(s.risk_score),
                        }} />
                      </div>
                      <span className={`text-xs font-semibold ${riskTextColor(s.risk_score)}`}>{s.risk_score}</span>
                    </div>
                  ) : <span className="text-t-quaternary text-xxs">—</span>}
                </td>
                <td className="td text-center">
                  {s.chain_valid === true ? <CheckCircle2 size={12} className="text-emerald-400 mx-auto" />
                   : s.chain_valid === false ? <XCircle size={12} className="text-red-400 mx-auto" />
                   : <span className="text-t-quaternary text-xxs">—</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function MetricCard({ label, value, suffix, color, icon: Icon }) {
  return (
    <div className="card-hover p-3 animate-in">
      <div className="section-label flex items-center gap-1">
        {Icon && <Icon size={10} />} {label}
      </div>
      <div className={`text-lg font-bold mt-0.5 ${color || 'text-t-primary'}`}>
        {value}{suffix && <span className="text-xs text-t-quaternary">{suffix}</span>}
      </div>
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
