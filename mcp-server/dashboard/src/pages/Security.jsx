import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, AlertTriangle, CheckCircle2, XCircle, Zap, TrendingUp } from 'lucide-react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'
import { fetchSessions, riskBadge, riskColor, riskTextColor } from '../api'

export default function Security() {
  const [loading, setLoading] = useState(true)
  const [riskData, setRiskData] = useState([])
  const navigate = useNavigate()

  useEffect(() => {
    // Use session_index data directly — no per-session API calls needed
    fetchSessions()
      .then((d) => {
        const sess = d.sessions || []
        setRiskData(sess.map(s => ({
          id: s.session_id.substring(0, 8),
          full_id: s.session_id,
          score: s.risk_score || 0,
          level: s.risk_level || (s.risk_score >= 75 ? 'critical' : s.risk_score >= 50 ? 'high' : s.risk_score >= 25 ? 'medium' : 'low'),
          patterns: s.patterns_count || 0,
          findings: s.findings_count || 0,
          verified: s.chain_valid,
        })))
      })
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [])

  if (loading) return (
    <div className="flex items-center justify-center h-full">
      <div className="w-5 h-5 border-2 border-brand border-t-transparent rounded-full animate-spin" />
    </div>
  )

  const totalPatterns = riskData.reduce((s, r) => s + r.patterns, 0)
  const totalFindings = riskData.reduce((s, r) => s + r.findings, 0)
  const avgScore = riskData.length > 0 ? Math.round(riskData.reduce((s, r) => s + r.score, 0) / riskData.length) : 0
  const criticalCount = riskData.filter(r => r.score >= 75).length
  const verifiedCount = riskData.filter(r => r.verified === true).length

  return (
    <div className="p-5 max-w-7xl mx-auto space-y-4">
      <div>
        <h1 className="text-xl font-semibold text-t-primary">Security Overview</h1>
        <p className="text-xxs text-t-quaternary mt-0.5">Cross-session risk analysis · {riskData.length} sessions</p>
      </div>

      <div className="grid grid-cols-5 gap-2.5 animate-in delay-1">
        <MC icon={TrendingUp} label="Avg Risk" value={avgScore} sub="/100" color={riskTextColor(avgScore)} />
        <MC icon={AlertTriangle} label="Critical" value={criticalCount} sub="sessions" color="text-danger" />
        <MC icon={Zap} label="Patterns" value={totalPatterns} sub="detected" color="text-warning" />
        <MC icon={Shield} label="Findings" value={totalFindings} sub="ontology" color="text-risk-high" />
        <MC icon={CheckCircle2} label="Verified" value={`${verifiedCount}/${riskData.length}`} sub="chains" color="text-emerald-400" />
      </div>

      {riskData.length > 0 && (
        <div className="card p-4 animate-in delay-2">
          <div className="section-label mb-3">Risk Score by Session</div>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={riskData}>
              <XAxis dataKey="id" tick={{ fontSize: 10, fill: '#6e7681' }} axisLine={{ stroke: 'rgba(255,255,255,0.04)' }} tickLine={false} />
              <YAxis domain={[0, 100]} tick={{ fontSize: 10, fill: '#6e7681' }} axisLine={{ stroke: 'rgba(255,255,255,0.04)' }} tickLine={false} />
              <Tooltip content={({ active, payload }) => {
                if (!active || !payload?.[0]) return null
                const d = payload[0].payload
                return (
                  <div className="card p-2.5 text-xxs border border-white/[0.1]">
                    <div className="font-mono text-t-primary mb-0.5">{d.full_id}</div>
                    <div className="text-t-secondary">Score: <span className="font-bold">{d.score}</span> · {d.level}</div>
                    <div className="text-t-tertiary">Patterns: {d.patterns} · Findings: {d.findings}</div>
                  </div>
                )
              }} />
              <Bar dataKey="score" radius={[3, 3, 0, 0]} cursor="pointer"
                onClick={(d) => navigate(`/sessions/${d.full_id}`)}>
                {riskData.map((d, i) => <Cell key={i} fill={riskColor(d.score)} fillOpacity={0.75} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      <div className="card overflow-hidden animate-in delay-3">
        <div className="px-3 py-2 border-b border-white/[0.04]">
          <div className="section-label">Session Risk Matrix</div>
        </div>
        <table className="w-full">
          <thead><tr>
            <th className="th">Session</th><th className="th">Score</th>
            <th className="th">Level</th><th className="th">Patterns</th>
            <th className="th">Findings</th><th className="th text-center">Chain</th>
          </tr></thead>
          <tbody>
            {riskData.map(r => (
              <tr key={r.full_id} className="tr-hover" onClick={() => navigate(`/sessions/${r.full_id}`)}>
                <td className="td font-mono text-xs text-brand">{r.id}…</td>
                <td className="td">
                  <div className="flex items-center gap-1.5">
                    <div className="w-12 h-1 bg-white/[0.04] rounded-full overflow-hidden">
                      <div className="h-full rounded-full" style={{ width: `${r.score}%`, background: riskColor(r.score) }} />
                    </div>
                    <span className={`text-xs font-semibold ${riskTextColor(r.score)}`}>{r.score}</span>
                  </div>
                </td>
                <td className="td"><span className={`badge ${riskBadge(r.level)}`}>{r.level}</span></td>
                <td className="td text-xs">{r.patterns}</td>
                <td className="td text-xs">{r.findings}</td>
                <td className="td text-center">
                  {r.verified === true ? <CheckCircle2 size={12} className="text-emerald-400 mx-auto" />
                   : r.verified === false ? <XCircle size={12} className="text-red-400 mx-auto" />
                   : <span className="text-t-quaternary">—</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function MC({ icon: Icon, label, value, sub, color }) {
  return (
    <div className="card p-2.5">
      <div className="section-label flex items-center gap-1"><Icon size={10} /> {label}</div>
      <div className={`text-xl font-black mt-0.5 ${color}`}>{value}</div>
      {sub && <div className="text-micro text-t-quaternary">{sub}</div>}
    </div>
  )
}
