import { useState, useEffect } from 'react'
import { Brain, Shield, Lock, AlertTriangle, Loader2, Zap } from 'lucide-react'
import { fetchSessionData, fetchSessions, analyzeSession } from '../api'

const MODES = [
  {
    id: 'local', name: 'Zero-Trust Analysis', icon: Lock,
    desc: 'Data never leaves your machine. Powered by local LLM.',
    badge: 'LOCAL', badgeClass: 'badge-pass',
    needsKey: false, isPro: false,
  },
  {
    id: 'cloud', name: 'Advanced Analysis', icon: Zap,
    desc: 'Deep security reasoning via cloud LLM. 14 PII patterns masked before sending.',
    badge: 'CLOUD', badgeClass: 'badge-high',
    needsKey: true, isPro: true,
  },
]

export default function Analysis() {
  const [mode, setMode] = useState('local')
  const [apiKey, setApiKey] = useState('')
  const [sessions, setSessions] = useState([])
  const [selectedSession, setSelectedSession] = useState(null)
  const [analyzing, setAnalyzing] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    fetchSessions().then(d => {
      const s = d.sessions || []
      setSessions(s)
      if (s.length > 0) setSelectedSession(s[0].session_id)
    }).catch(() => {})
  }, [])

  const runAnalysis = async () => {
    if (!selectedSession) return
    if (mode === 'cloud' && !apiKey.trim()) {
      setError('API key is required for Advanced Analysis')
      return
    }

    setAnalyzing(true)
    setError(null)
    setResult(null)

    try {
      const sessionData = await fetchSessionData(selectedSession)
      const sessionText = JSON.stringify({
        session_id: sessionData.session_id,
        records: (sessionData.records || []).slice(0, 200),
        risk: sessionData.risk,
        verification: sessionData.verification,
        session_log: (sessionData.session_log || []).slice(0, 100),
      })

      // Cloud mode auto-detects provider from API key format
      const provider = mode === 'local' ? 'local' : (apiKey.startsWith('sk-ant') ? 'anthropic' : 'openai')
      const res = await analyzeSession(
        apiKey || '', sessionText, provider,
        mode === 'local' ? 'llama3.2' : undefined,
        selectedSession
      )

      if (res.error) {
        setError(res.error)
      } else {
        // Parse result
        let parsed = res.result
        if (typeof parsed === 'string') {
          try {
            // Extract JSON from markdown code blocks
            let json = parsed
            if (json.includes('```json')) json = json.split('```json')[1].split('```')[0]
            else if (json.includes('```')) json = json.split('```')[1].split('```')[0]
            parsed = JSON.parse(json.trim())
          } catch {
            parsed = { summary: parsed, risk_score: 0, risk_level: 'UNKNOWN', findings: [], recommendations: [] }
          }
        }
        setResult(parsed)
      }
    } catch (e) {
      setError(e.message)
    } finally {
      setAnalyzing(false)
    }
  }

  const currentMode = MODES.find(m => m.id === mode)

  return (
    <div className="p-5 max-w-5xl mx-auto space-y-4">
      <div>
        <h1 className="text-xl font-semibold text-t-primary flex items-center gap-2">
          <Brain size={20} /> AI Security Analysis
        </h1>
        <p className="text-xxs text-t-quaternary mt-0.5">Deep security analysis powered by LLM — choose your trust level</p>
      </div>

      {/* Mode Selection */}
      <div className="grid grid-cols-2 gap-3 animate-in delay-1">
        {MODES.map(m => (
          <button key={m.id} onClick={() => setMode(m.id)}
            className={`card p-4 text-left transition-all ${
              mode === m.id ? 'ring-1 ring-brand' : 'hover:border-white/[0.1]'
            }`}>
            <div className="flex items-center justify-between mb-1.5">
              <m.icon size={16} className={mode === m.id ? 'text-brand' : 'text-t-quaternary'} />
              <span className={`badge ${m.badgeClass} text-micro`}>{m.badge}</span>
            </div>
            <div className="text-sm font-medium text-t-primary">{m.name}</div>
            <div className="text-xxs text-t-quaternary mt-0.5">{m.desc}</div>
          </button>
        ))}
      </div>

      {/* Config */}
      <div className="card p-4 space-y-3 animate-in delay-2">
        {/* Session selector */}
        <div>
          <label className="text-xxs text-t-quaternary block mb-1">Session</label>
          <select value={selectedSession || ''} onChange={e => setSelectedSession(e.target.value)}
            className="w-full bg-app border border-white/[0.08] rounded-md px-3 py-1.5 text-sm text-t-primary focus:outline-none focus:ring-1 focus:ring-brand">
            {sessions.map(s => (
              <option key={s.session_id} value={s.session_id}>
                {s.session_id.substring(0, 8)} — {s.record_count || 0} records
              </option>
            ))}
          </select>
        </div>

        {/* API Key (cloud only) */}
        {currentMode?.needsKey && (
          <div>
            <label className="text-xxs text-t-quaternary block mb-1">
              API Key
              <span className="text-t-quaternary ml-1">(Anthropic or OpenAI — auto-detected)</span>
            </label>
            <input type="password" value={apiKey} onChange={e => setApiKey(e.target.value)}
              placeholder="sk-ant-... or sk-..."
              className="w-full bg-app border border-white/[0.08] rounded-md px-3 py-1.5 text-sm text-t-primary focus:outline-none focus:ring-1 focus:ring-brand font-mono" />
          </div>
        )}

        {/* Zero-trust info for local */}
        {mode === 'local' && (
          <div className="flex items-start gap-2 p-2.5 rounded-md bg-emerald-500/5 border border-emerald-500/20">
            <Lock size={14} className="text-emerald-400 flex-shrink-0 mt-0.5" />
            <div className="text-xxs text-t-tertiary">
              <strong className="text-emerald-400">Zero-Trust:</strong> All data stays on your machine. Requires <code className="text-brand">ollama serve</code> running locally.
            </div>
          </div>
        )}

        {/* Zero-trust exception for cloud */}
        {currentMode?.isPro && (
          <div className="flex items-start gap-2 p-2.5 rounded-md bg-warning/5 border border-warning/20">
            <AlertTriangle size={14} className="text-warning flex-shrink-0 mt-0.5" />
            <div className="text-xxs text-t-tertiary space-y-1">
              <p><strong className="text-warning">Zero-Trust Exception:</strong> Session data is sent to an external LLM API for deep analysis. This breaks the zero-trust guarantee for the analysis step only.</p>
              <p>All monitoring, recording, and hash-chain verification remain <strong className="text-t-secondary">fully local and tamper-proof.</strong></p>
              <p>Security: <strong className="text-t-secondary">14 PII patterns masked</strong> before sending (API keys, passwords, emails, SSH keys, JWT, etc). Your API key is used directly and never stored.</p>
            </div>
          </div>
        )}

        <button onClick={runAnalysis} disabled={analyzing || !selectedSession}
          className={`w-full py-2 rounded-md text-sm font-medium transition-all ${
            analyzing ? 'bg-brand/30 text-brand cursor-wait' : 'bg-brand text-white hover:bg-brand/90'
          }`}>
          {analyzing ? (
            <span className="flex items-center justify-center gap-2">
              <Loader2 size={14} className="animate-spin" /> Analyzing...
            </span>
          ) : (
            <span className="flex items-center justify-center gap-2">
              <Brain size={14} /> Run Analysis
            </span>
          )}
        </button>
      </div>

      {/* Error */}
      {error && (
        <div className="card p-3 border-red-500/30">
          <div className="text-sm text-red-400">{error}</div>
        </div>
      )}

      {/* Results */}
      {result && <div className="scale-in"><AnalysisResult result={result} /></div>}
    </div>
  )
}

function AnalysisResult({ result }) {
  const score = result.risk_score ?? 0
  const level = result.risk_level || 'UNKNOWN'
  const findings = result.findings || []
  const recs = result.recommendations || []
  const summary = result.summary || ''
  const behavioral = result.behavioral_summary || {}
  const graph = result.graph_analysis || {}

  const levelColor = {
    LOW: 'text-emerald-400', MEDIUM: 'text-amber-400',
    HIGH: 'text-orange-400', CRITICAL: 'text-red-400',
  }[level] || 'text-t-tertiary'

  const severityColor = {
    CRITICAL: 'border-red-500', HIGH: 'border-orange-500',
    MEDIUM: 'border-amber-500', LOW: 'border-emerald-500', INFO: 'border-blue-500',
  }

  return (
    <div className="space-y-3">
      {/* Score card */}
      <div className="card p-5 text-center">
        <div className={`text-4xl font-black ${levelColor}`}>{score}</div>
        <div className={`text-lg font-bold ${levelColor} mt-1`}>{level}</div>
        <p className="text-xs text-t-tertiary mt-2 max-w-lg mx-auto">{summary}</p>
      </div>

      {/* Graph Analysis */}
      {(graph.critical_entities_accessed > 0 || graph.threat_paths_found > 0 || (graph.data_flow_risks || []).length > 0) && (
        <div className="card p-4">
          <div className="section-label mb-2">Ontology Graph Analysis</div>
          <div className="grid grid-cols-3 gap-3 text-center mb-3">
            <div>
              <div className="text-xl font-bold text-red-400">{graph.critical_entities_accessed || 0}</div>
              <div className="text-xxs text-t-quaternary">Critical Entities</div>
            </div>
            <div>
              <div className="text-xl font-bold text-orange-400">{graph.threat_paths_found || 0}</div>
              <div className="text-xxs text-t-quaternary">Threat Paths</div>
            </div>
            <div>
              <div className="text-xl font-bold text-t-primary">{graph.risk_score_adjustment || '+0'}</div>
              <div className="text-xxs text-t-quaternary">Score Adjustment</div>
            </div>
          </div>
          {(graph.data_flow_risks || []).length > 0 && (
            <div className="space-y-1">
              {graph.data_flow_risks.map((r, i) => (
                <div key={i} className="text-xxs text-t-tertiary bg-app rounded p-2 font-mono">{r}</div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Behavioral summary */}
      {behavioral.total_actions > 0 && (
        <div className="card p-4">
          <div className="section-label mb-2">Behavioral Summary</div>
          <div className="grid grid-cols-3 gap-3 text-center">
            <div>
              <div className="text-xl font-bold text-t-primary">{behavioral.total_actions}</div>
              <div className="text-xxs text-t-quaternary">Actions</div>
            </div>
            <div>
              <div className="text-xl font-bold text-t-primary">{behavioral.user_requests}</div>
              <div className="text-xxs text-t-quaternary">User Requests</div>
            </div>
            <div>
              <div className="text-xl font-bold text-t-primary">{behavioral.anomaly_count}</div>
              <div className="text-xxs text-t-quaternary">Anomalies</div>
            </div>
          </div>
          {behavioral.tools_used && Object.keys(behavioral.tools_used).length > 0 && (
            <div className="mt-3 pt-3 border-t border-white/[0.04]">
              <div className="text-xxs text-t-quaternary mb-1.5">Tools Used</div>
              <div className="flex flex-wrap gap-1.5">
                {Object.entries(behavioral.tools_used).map(([tool, count]) => (
                  <span key={tool} className="badge badge-info text-micro">{tool}: {count}</span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Findings */}
      {findings.length > 0 && (
        <div className="card p-4">
          <div className="section-label mb-2">Findings ({findings.length})</div>
          <div className="space-y-2">
            {findings.map((f, i) => (
              <div key={i} className={`p-3 rounded-md bg-app border-l-2 ${severityColor[f.severity] || 'border-gray-500'}`}>
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium text-t-primary">{f.title}</span>
                  <span className={`badge ${f.severity === 'CRITICAL' ? 'badge-critical' : f.severity === 'HIGH' ? 'badge-high' : f.severity === 'MEDIUM' ? 'badge-medium' : 'badge-low'}`}>
                    {f.severity}
                  </span>
                </div>
                <p className="text-xxs text-t-tertiary mt-1">{f.description}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Recommendations */}
      {recs.length > 0 && (
        <div className="card p-4">
          <div className="section-label mb-2">Recommendations</div>
          <ul className="space-y-1.5">
            {recs.map((r, i) => (
              <li key={i} className="text-xs text-t-tertiary flex items-start gap-2">
                <Shield size={11} className="text-brand flex-shrink-0 mt-0.5" />
                {r}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
