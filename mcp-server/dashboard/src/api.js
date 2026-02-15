const BASE = window.location.origin

export async function fetchSessions(includeEmpty = false) {
  const url = includeEmpty
    ? `${BASE}/api/sessions?include_empty=true`
    : `${BASE}/api/sessions`
  const res = await fetch(url)
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json()
}

export async function fetchSessionData(sessionId) {
  const res = await fetch(`${BASE}/api/sessions/${sessionId}`)
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json()
}

export async function fetchLatestSession() {
  const res = await fetch(`${BASE}/api/sessions/latest`)
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json()
}

export async function analyzeSession(apiKey, sessionData, provider = 'local', model, sessionId) {
  const body = { api_key: apiKey, session_data: sessionData, provider }
  if (model) body.model = model
  if (sessionId) body.session_id = sessionId
  const res = await fetch(`${BASE}/api/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json()
}

export async function refreshSessions() {
  const res = await fetch(`${BASE}/api/refresh`, { method: 'POST' })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json()
}

// ── Normalizers ──
export function getRiskLevel(risk) {
  return risk?.overall_risk || risk?.risk_level || 'unknown'
}

export function getOwaspItems(owasp) {
  return owasp?.checks || owasp?.items || []
}

export function getDriftAnomalies(drift) {
  return drift?.anomalies || []
}

// ── Display helpers ──
export function riskBadge(level) {
  const l = (level || '').toLowerCase()
  if (l === 'critical') return 'badge-critical'
  if (l === 'high') return 'badge-high'
  if (l === 'medium') return 'badge-medium'
  if (l === 'low') return 'badge-low'
  return 'badge-info'
}

export function riskColor(score) {
  if (score >= 75) return '#ef4444'
  if (score >= 50) return '#f97316'
  if (score >= 25) return '#eab308'
  return '#10b981'
}

export function riskTextColor(score) {
  if (score >= 75) return 'text-red-400'
  if (score >= 50) return 'text-orange-400'
  if (score >= 25) return 'text-amber-400'
  return 'text-emerald-400'
}

export function formatTime(ts) {
  if (!ts) return '-'
  try {
    return new Date(ts).toLocaleString()
  } catch {
    return ts
  }
}

export function shortHash(h) {
  if (!h) return '-'
  return h.substring(0, 12) + '…'
}

export function statusBadge(s) {
  if (s === 'PASS') return 'badge-pass'
  if (s === 'PARTIAL' || s === 'WARN') return 'badge-warn'
  if (s === 'FAIL') return 'badge-fail'
  return 'badge-info'
}

// ── Ontology API ──
export async function fetchOntologyExport(sessionId) {
  const res = await fetch(`${BASE}/api/sessions/${sessionId}/ontology`)
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json()
}

export async function fetchOntologyOverview() {
  const res = await fetch(`${BASE}/api/ontology/export`)
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json()
}

export function downloadOntology(data) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/ld+json' })
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = `inalign-ontology-${data.session_id?.substring(0, 8) || 'all'}.jsonld`
  a.click()
  URL.revokeObjectURL(a.href)
}

// ── Download helpers ──
export function downloadJSON(data, prefix = 'inalign') {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = `${prefix}-${data.session_id?.substring(0, 8) || 'export'}.json`
  a.click()
  URL.revokeObjectURL(a.href)
}

export function downloadCSV(records, prefix = 'inalign') {
  const rows = [['sequence', 'type', 'action', 'hash', 'previous_hash', 'timestamp']]
  for (const r of (records || [])) {
    rows.push([
      r.sequence, r.type,
      `"${(r.name || '').replace(/"/g, '""')}"`,
      r.hash, r.previous_hash || 'genesis', r.timestamp || ''
    ])
  }
  const csv = rows.map(r => r.join(',')).join('\n')
  const blob = new Blob([csv], { type: 'text/csv' })
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = `${prefix}-chain.csv`
  a.click()
  URL.revokeObjectURL(a.href)
}
