import { NavLink } from 'react-router-dom'
import { LayoutDashboard, List, Shield, Brain, RefreshCw } from 'lucide-react'
import { useState } from 'react'
import { refreshSessions } from '../api'

const NAV = [
  { to: '/', icon: LayoutDashboard, label: 'Overview' },
  { to: '/sessions', icon: List, label: 'Sessions' },
  { to: '/security', icon: Shield, label: 'Security' },
  { to: '/analysis', icon: Brain, label: 'AI Analysis' },
]

export default function Layout({ children }) {
  const [refreshing, setRefreshing] = useState(false)

  const handleRefresh = async () => {
    setRefreshing(true)
    try {
      await refreshSessions()
      window.location.reload()
    } catch (e) {
      console.error('Refresh failed:', e)
    } finally {
      setRefreshing(false)
    }
  }

  return (
    <div className="flex h-screen overflow-hidden bg-app">
      {/* Sidebar — Palantir narrow nav */}
      <aside className="w-52 flex flex-col flex-shrink-0 bg-surface border-r border-white/[0.06]">
        {/* Logo */}
        <div className="px-4 py-4 border-b border-white/[0.04]">
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded-md flex items-center justify-center text-xs font-black text-white bg-brand">
              IA
            </div>
            <div>
              <div className="text-sm font-semibold text-t-primary tracking-tight">InALign</div>
              <div className="text-micro text-t-quaternary tracking-widest uppercase">Governance</div>
            </div>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 px-2 py-3 space-y-0.5">
          {NAV.map(({ to, icon: Icon, label }) => (
            <NavLink key={to} to={to} end={to === '/'}
              className={({ isActive }) =>
                `flex items-center gap-2 px-3 py-[7px] rounded-md text-sm transition-all duration-100 ${
                  isActive
                    ? 'bg-brand/10 text-brand font-medium'
                    : 'text-t-tertiary hover:text-t-secondary hover:bg-white/[0.03]'
                }`
              }>
              <Icon size={15} strokeWidth={1.8} />
              {label}
            </NavLink>
          ))}
        </nav>

        {/* Footer */}
        <div className="px-3 py-3 border-t border-white/[0.04]">
          <button onClick={handleRefresh} disabled={refreshing}
            className="flex items-center gap-1.5 text-xxs text-t-quaternary hover:text-t-tertiary transition-colors w-full">
            <RefreshCw size={11} className={refreshing ? 'animate-spin' : ''} />
            {refreshing ? 'Syncing…' : 'Sync Sessions'}
          </button>
          <div className="text-micro text-t-quaternary mt-1.5 font-mono opacity-50">
            v0.9.0 · local · zero-trust
          </div>
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 overflow-auto bg-app">
        {children}
      </main>
    </div>
  )
}
