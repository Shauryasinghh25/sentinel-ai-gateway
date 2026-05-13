import { useState, useEffect } from 'react'
import { AlertTriangle, Filter } from 'lucide-react'
import { apiClient, RequestEvent } from '../api/client'
import ThreatTable from '../components/ThreatTable'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  ScatterChart, Scatter, Cell
} from 'recharts'

import BackendOffline from '../components/BackendOffline'
import EmptyState from '../components/EmptyState'

const ATTACK_COLORS: Record<string, string> = {
  jailbreak: '#ef4444',
  prompt_injection: '#f97316',
  pii_leakage: '#eab308',
  toxicity: '#8b5cf6',
  role_override: '#f43f5e',
  tool_manipulation: '#06b6d4',
  rag_poisoning: '#10b981',
  unknown: '#64748b',
}

export default function Threats() {
  const [events, setEvents] = useState<RequestEvent[]>([])
  const [filter, setFilter] = useState<string>('all')
  const [hours, setHours] = useState(24)
  const [error, setError] = useState(false)

  const fetch = async () => {
    setError(false)
    try {
      const r = await apiClient.getEvents(500)
      setEvents(r.events)
    } catch {
      if (import.meta.env.VITE_DEMO_MODE === 'true') {
        // Generate demo threat events
        const ATTACKS = ['jailbreak', 'prompt_injection', 'pii_leakage', 'toxicity', 'role_override']
        const demo: RequestEvent[] = Array.from({ length: 50 }, (_, i) => ({
          event_id: `demo-${i}`,
          timestamp: new Date(Date.now() - i * 180_000).toISOString(),
          request_id: `req-${i}`,
          provider: ['openai', 'anthropic', 'google'][i % 3],
          model: ['gpt-4o-mini', 'claude-3-haiku', 'gemini-1.5-flash'][i % 3],
          action: (i % 5 === 0 ? 'allowed' : 'blocked') as any,
          risk_score: i % 5 === 0 ? 0.05 + Math.random() * 0.2 : 0.7 + Math.random() * 0.3,
          attack_types: i % 5 === 0 ? [] : [ATTACKS[i % ATTACKS.length]],
          latency_ms: Math.random() * 400 + 50,
          tokens: Math.floor(Math.random() * 600 + 100),
          policy_id: 'default',
        }))
        setEvents(demo)
      } else {
        setError(true)
        setEvents([])
      }
    }
  }

  useEffect(() => {
    fetch()
    const interval = setInterval(fetch, 15_000)
    return () => clearInterval(interval)
  }, [])

  const threats = events.filter(e => e.action === 'blocked' || e.action === 'flagged')
  const filtered = filter === 'all'
    ? threats
    : threats.filter(e => e.attack_types.includes(filter))

  // Attack type breakdown for bar chart
  const attackBreakdown: Record<string, number> = {}
  for (const e of threats) {
    for (const at of e.attack_types) {
      attackBreakdown[at] = (attackBreakdown[at] || 0) + 1
    }
  }
  const barData = Object.entries(attackBreakdown)
    .map(([name, count]) => ({ name: name.replace(/_/g, ' '), count, fill: ATTACK_COLORS[name] || '#6b7280' }))
    .sort((a, b) => b.count - a.count)

  const attackTypes = [...new Set(threats.flatMap(e => e.attack_types))]

  return (
    <div className="page-enter space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-3">
          <AlertTriangle className="text-red-400" size={28} />
          Threat Intelligence
        </h1>
        <p className="text-slate-400 text-sm mt-1">
          {threats.length} threats detected in the last {hours} hours
        </p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-4">
        <div className="metric-card">
          <p className="text-3xl font-bold text-red-400">{threats.length}</p>
          <p className="text-sm text-slate-400 mt-1">Total Threats</p>
        </div>
        <div className="metric-card">
          <p className="text-3xl font-bold text-orange-400">
            {threats.filter(e => e.risk_score >= 0.9).length}
          </p>
          <p className="text-sm text-slate-400 mt-1">Critical (≥90%)</p>
        </div>
        <div className="metric-card">
          <p className="text-3xl font-bold text-yellow-400">{attackTypes.length}</p>
          <p className="text-sm text-slate-400 mt-1">Unique Attack Types</p>
        </div>
      </div>

      {/* Attack type chart */}
      <div className="card-glass p-6">
        <h3 className="section-title mb-1">Attack Distribution</h3>
        <p className="section-subtitle mb-5">Threat frequency by category</p>
        <ResponsiveContainer width="100%" height={220}>
          <BarChart data={barData}>
            <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 11 }} axisLine={false} tickLine={false} />
            <YAxis tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
            <Tooltip
              contentStyle={{ background: '#1e293b', border: '1px solid rgba(99,102,241,0.3)', borderRadius: 8 }}
            />
            <Bar dataKey="count" radius={[4, 4, 0, 0]} name="Count">
              {barData.map((entry, index) => (
                <Cell key={index} fill={entry.fill} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Filter */}
      <div className="flex items-center gap-2 flex-wrap">
        <Filter size={14} className="text-slate-400" />
        <button
          onClick={() => setFilter('all')}
          className={`px-3 py-1.5 rounded-full text-xs font-medium transition-all ${filter === 'all' ? 'bg-indigo-600 text-white' : 'bg-slate-800 text-slate-400'}`}
        >
          All ({threats.length})
        </button>
        {attackTypes.map(at => (
          <button
            key={at}
            onClick={() => setFilter(at)}
            className={`px-3 py-1.5 rounded-full text-xs font-medium transition-all ${filter === at ? 'text-white' : 'bg-slate-800 text-slate-400'}`}
            style={filter === at ? { background: ATTACK_COLORS[at] || '#6366f1' } : {}}
          >
            {at.replace(/_/g, ' ')} ({attackBreakdown[at] || 0})
          </button>
        ))}
      </div>

      {/* Threat table */}
      <div className="card-glass p-6">
        <h3 className="section-title mb-4">Threat Events</h3>
        {error ? (
          <BackendOffline onRetry={fetch} />
        ) : filtered.length === 0 ? (
          <EmptyState 
            title="No threats observed yet" 
            message="We haven't detected any security threats matching your current filters." 
            icon={AlertTriangle} 
          />
        ) : (
          <ThreatTable events={filtered} maxRows={100} />
        )}
      </div>
    </div>
  )
}
