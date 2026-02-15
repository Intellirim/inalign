import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Search, ArrowUpDown, RefreshCw, Database, Hash, HardDrive, Clock, CheckCircle2, XCircle, Eye, EyeOff } from 'lucide-react'
import { fetchSessions, refreshSessions, formatTime, riskBadge, riskTextColor } from '../api'

export default function Sessions() {
  const [sessions, setSessions] = useState([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [sortKey, setSortKey] = useState('timestamp')
  const [sortDir, setSortDir] = useState('desc')
  const [refreshing, setRefreshing] = useState(false)
  const [showEmpty, setShowEmpty] = useState(false)
  const navigate = useNavigate()

  const load = () => {
    setLoading(true)
    fetchSessions(showEmpty)
      .then(d => setSessions(d.sessions || []))
      .catch(console.error)
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [showEmpty])

  const handleRefresh = async () => {
    setRefreshing(true)
    try {
      await refreshSessions()
      load()
    } catch (e) { console.error(e) }
    finally { setRefreshing(false) }
  }

  const toggleSort = (key) => {
    if (sortKey === key) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    else { setSortKey(key); setSortDir('desc') }
  }

  const filtered = sessions
    .filter(s => !search || s.session_id.toLowerCase().includes(search.toLowerCase()))
    .sort((a, b) => {
      let av = a[sortKey] ?? '', bv = b[sortKey] ?? ''
      if (av < bv) return sortDir === 'asc' ? -1 : 1
      if (av > bv) return sortDir === 'asc' ? 1 : -1
      return 0
    })

  const totalRecords = sessions.reduce((s, x) => s + (x.record_count || 0), 0)
  const totalSize = sessions.reduce((s, x) => s + (x.file_size_kb || 0), 0)
  const withRisk = sessions.filter(s => s.risk_score != null)

  return (
    <div className="p-5 max-w-7xl mx-auto space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-t-primary">Sessions</h1>
          <p className="text-xxs text-t-quaternary mt-0.5">
            {sessions.length} sessions · {showEmpty ? 'including empty' : 'active only'}
          </p>
        </div>
        <div className="flex items-center gap-1.5">
          <button onClick={() => setShowEmpty(!showEmpty)}
            className={`btn-ghost text-xxs ${showEmpty ? 'text-warning' : ''}`}>
            {showEmpty ? <EyeOff size={11} /> : <Eye size={11} />}
            {showEmpty ? 'Hide Empty' : 'Show Empty'}
          </button>
          <button onClick={handleRefresh} disabled={refreshing} className="btn-ghost">
            <RefreshCw size={11} className={refreshing ? 'animate-spin' : ''} />
            {refreshing ? 'Syncing…' : 'Sync'}
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-2.5 animate-in delay-1">
        <MiniStat icon={Database} label="Sessions" value={sessions.length} />
        <MiniStat icon={Hash} label="Total Records" value={totalRecords.toLocaleString()} />
        <MiniStat icon={HardDrive} label="Storage"
          value={totalSize > 1024 ? `${(totalSize/1024).toFixed(1)} MB` : `${Math.round(totalSize)} KB`} />
        <MiniStat icon={Clock} label="Latest"
          value={sessions.length > 0 ? formatTime(sessions[0]?.timestamp) : '-'} small />
      </div>

      {/* Search */}
      <div className="relative">
        <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-t-quaternary" />
        <input type="text" placeholder="Search by session ID…" value={search}
          onChange={e => setSearch(e.target.value)} className="input w-full pl-8" />
      </div>

      {/* Table */}
      <div className="card overflow-hidden animate-in delay-2">
        {loading ? (
          <div className="p-10 text-center">
            <div className="w-4 h-4 border-2 border-brand border-t-transparent rounded-full animate-spin mx-auto" />
            <p className="text-xxs text-t-quaternary mt-2">Loading sessions…</p>
          </div>
        ) : filtered.length === 0 ? (
          <div className="p-10 text-center text-xxs text-t-quaternary">No sessions found</div>
        ) : (
          <table className="w-full">
            <thead><tr>
              <SH label="Session ID" k="session_id" cur={sortKey} dir={sortDir} onSort={toggleSort} />
              <SH label="Time" k="timestamp" cur={sortKey} dir={sortDir} onSort={toggleSort} />
              <SH label="Records" k="record_count" cur={sortKey} dir={sortDir} onSort={toggleSort} />
              <SH label="Size" k="file_size_kb" cur={sortKey} dir={sortDir} onSort={toggleSort} />
              <SH label="Risk" k="risk_score" cur={sortKey} dir={sortDir} onSort={toggleSort} />
              <th className="th text-center">Chain</th>
              <th className="th text-right pr-4">Actions</th>
            </tr></thead>
            <tbody>
              {filtered.map(s => (
                <tr key={s.session_id} className="tr-hover"
                  onClick={() => navigate(`/sessions/${s.session_id}`)}>
                  <td className="td font-mono text-xs text-brand">{s.session_id}</td>
                  <td className="td text-xs">{formatTime(s.timestamp)}</td>
                  <td className="td text-xs">{s.record_count || '-'}</td>
                  <td className="td text-xs text-t-quaternary">{s.file_size_kb ? `${s.file_size_kb} KB` : '-'}</td>
                  <td className="td">
                    {s.risk_score != null ? (
                      <div className="flex items-center gap-1.5">
                        <div className="w-12 h-1 bg-white/[0.04] rounded-full overflow-hidden">
                          <div className="h-full rounded-full" style={{
                            width: `${s.risk_score}%`, background: riskTextColor(s.risk_score).includes('red') ? '#ef4444' :
                              riskTextColor(s.risk_score).includes('orange') ? '#f97316' :
                              riskTextColor(s.risk_score).includes('amber') ? '#eab308' : '#10b981'
                          }} />
                        </div>
                        <span className={`text-xs font-semibold ${riskTextColor(s.risk_score)}`}>{s.risk_score}</span>
                      </div>
                    ) : <span className="text-xxs text-t-quaternary">—</span>}
                  </td>
                  <td className="td text-center">
                    {s.chain_valid === true ? <CheckCircle2 size={12} className="text-emerald-400 mx-auto" />
                     : s.chain_valid === false ? <XCircle size={12} className="text-red-400 mx-auto" />
                     : <span className="text-t-quaternary text-xxs">—</span>}
                  </td>
                  <td className="td text-right pr-4">
                    <span className="text-xxs text-brand hover:text-accent-indigo font-medium">View →</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}

function MiniStat({ icon: Icon, label, value, small }) {
  return (
    <div className="card p-2.5">
      <div className="section-label flex items-center gap-1"><Icon size={10} /> {label}</div>
      <div className={`font-semibold text-t-primary mt-0.5 ${small ? 'text-xs' : 'text-lg'}`}>{value}</div>
    </div>
  )
}

function SH({ label, k, cur, dir, onSort }) {
  return (
    <th className="th cursor-pointer hover:text-t-tertiary" onClick={() => onSort(k)}>
      <span className="flex items-center gap-0.5">
        {label}
        <ArrowUpDown size={9} className={cur === k ? 'text-brand' : 'text-t-quaternary/50'} />
      </span>
    </th>
  )
}
