import { useEffect, useState } from 'react'
import { Shield, TrendingUp, AlertTriangle, Activity, Zap, CheckCircle, Clock, Cpu } from 'lucide-react'
import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, PieChart, Pie, Cell, LineChart, Line
} from 'recharts'

import MetricCard from '../components/MetricCard'
import ThreatTable from '../components/ThreatTable'
import BackendOffline from '../components/BackendOffline'
import { apiClient, DashboardStats, RequestEvent } from '../api/client'

const THREAT_COLORS: Record<string, string> = {
  jailbreak: '#ef4444',
  prompt_injection: '#f97316',
  pii_leakage: '#eab308',
  toxicity: '#8b5cf6',
  role_override: '#f43f5e',
  tool_manipulation: '#06b6d4',
  rag_poisoning: '#10b981',
  unicode_obfuscation: '#6366f1',
  unknown: '#64748b',
}

const PIE_COLORS = ['#6366f1', '#ef4444', '#f97316', '#eab308', '#8b5cf6', '#06b6d4', '#10b981', '#f43f5e']

// ── Mock real-time feed ─────────────────────────────────────────────────────
function useLiveStats(refreshMs = 10000) {
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [events, setEvents] = useState<RequestEvent[]>([])
  const [error, setError] = useState<string | null>(null)
  const [isDemoMode, setIsDemoMode] = useState(import.meta.env.VITE_DEMO_MODE === 'true')

  const fetchAll = async () => {
    try {
      const [s, e] = await Promise.all([
        apiClient.getStats(24),
        apiClient.getEvents(100),
      ])
      setStats(s)
      setEvents(e.events)
      setError(null)
    } catch (err: any) {
      if (import.meta.env.VITE_DEMO_MODE === 'true') {
        if (!stats) setStats(getDemoStats())
        setError('Demo Mode Active')
      } else {
        setError('Backend service unreachable')
        setStats(null)
      }
    }
  }

  useEffect(() => {
    fetchAll()
    const interval = setInterval(fetchAll, refreshMs)
    return () => clearInterval(interval)
  }, [])

  return { stats, events, error, isDemoMode, refresh: fetchAll }
}

function getDemoStats(): DashboardStats {
  return {
    total_requests: 2847,
    blocked_requests: 438,
    allowed_requests: 2247,
    flagged_requests: 102,
    sanitized_requests: 60,
    block_rate: 0.154,
    avg_risk_score: 0.243,
    avg_latency_ms: 187.4,
    total_tokens: 1_284_930,
    attack_breakdown: {
      jailbreak: 189,
      prompt_injection: 134,
      pii_leakage: 67,
      toxicity: 28,
      role_override: 13,
      tool_manipulation: 7,
    },
    provider_breakdown: { openai: 1842, anthropic: 634, google: 271, ollama: 100 },
    model_breakdown: { 'gpt-4o-mini': 1200, 'gpt-4o': 642, 'claude-3-haiku': 634, 'gemini-1.5-flash': 271 },
    requests_per_hour: Array.from({ length: 24 }, (_, h) => ({
      hour: h,
      total: Math.floor(Math.random() * 180 + 40),
      blocked: Math.floor(Math.random() * 40 + 5),
    })),
    top_threats: [
      { type: 'jailbreak', count: 189 },
      { type: 'prompt_injection', count: 134 },
      { type: 'pii_leakage', count: 67 },
      { type: 'toxicity', count: 28 },
      { type: 'role_override', count: 13 },
    ],
  }
}

// ── Custom tooltip ────────────────────────────────────────────────────────────
function CustomTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-slate-800 border border-indigo-500/30 rounded-lg p-3 shadow-xl">
      <p className="text-slate-400 text-xs mb-1">{label !== undefined ? `Hour ${label}:00` : ''}</p>
      {payload.map((p: any) => (
        <p key={p.name} className="text-sm font-semibold" style={{ color: p.color }}>
          {p.name}: {p.value?.toLocaleString()}
        </p>
      ))}
    </div>
  )
}

export default function Dashboard() {
  const { stats, events, error, isDemoMode, refresh } = useLiveStats(15_000)

  if (error && !stats && !isDemoMode) {
    return (
      <div className="page-enter py-12">
        <BackendOffline onRetry={refresh} />
      </div>
    )
  }

  if (!stats) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <div className="w-12 h-12 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin mx-auto mb-4" />
          <p className="text-slate-400">Loading dashboard...</p>
        </div>
      </div>
    )
  }

  const attackPieData = Object.entries(stats.attack_breakdown).map(([name, value]) => ({
    name: name.replace(/_/g, ' '),
    value,
  }))

  const providerData = Object.entries(stats.provider_breakdown).map(([name, value]) => ({
    name, value,
  }))

  return (
    <div className="page-enter space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <Shield className="text-indigo-400" size={28} />
            Security Dashboard
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            Real-time threat monitoring & observability
          </p>
        </div>
        
      <div className="flex items-center gap-3">
          {isDemoMode && (
            <span className="text-xs bg-blue-500/10 text-blue-400 border border-blue-500/30 px-3 py-1.5 rounded-lg flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-pulse inline-block" />
              Demo Mode — set SEED_DEMO_DATA=false for real traffic
            </span>
          )}
          {error && (
            <span className="text-xs bg-yellow-500/10 text-yellow-400 border border-yellow-500/30 px-3 py-1.5 rounded-lg">
              {error}
            </span>
          )}
          <span className="live-indicator">Live Feed</span>
          <span className="text-xs text-slate-500 font-mono">Last 24h</span>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-4 gap-4">
        <MetricCard
          title="Total Requests"
          value={stats.total_requests.toLocaleString()}
          icon={Activity}
          accent="indigo"
          trend="up"
          trendValue="+12% vs yesterday"
          subtitle="Across all providers"
        />
        <MetricCard
          title="Blocked Threats"
          value={stats.blocked_requests.toLocaleString()}
          icon={AlertTriangle}
          accent="red"
          trend="up"
          trendValue={`${(stats.block_rate * 100).toFixed(1)}% block rate`}
          subtitle="Injection, jailbreak, toxicity"
        />
        <MetricCard
          title="Avg Risk Score"
          value={`${(stats.avg_risk_score * 100).toFixed(1)}%`}
          icon={TrendingUp}
          accent="yellow"
          subtitle="Lower is better"
        />
        <MetricCard
          title="Avg Latency"
          value={`${stats.avg_latency_ms.toFixed(0)}ms`}
          icon={Clock}
          accent="green"
          subtitle="Security overhead"
        />
      </div>

      <div className="grid grid-cols-4 gap-4">
        <MetricCard
          title="Allowed"
          value={stats.allowed_requests.toLocaleString()}
          icon={CheckCircle}
          accent="green"
        />
        <MetricCard
          title="Sanitized"
          value={stats.sanitized_requests.toLocaleString()}
          icon={Shield}
          accent="indigo"
          subtitle="PII redacted"
        />
        <MetricCard
          title="Flagged"
          value={stats.flagged_requests.toLocaleString()}
          icon={Zap}
          accent="orange"
          subtitle="Needs review"
        />
        <MetricCard
          title="Total Tokens"
          value={(stats.total_tokens / 1_000_000).toFixed(2) + 'M'}
          icon={Cpu}
          accent="indigo"
          subtitle="Processed"
        />
      </div>

      {/* Charts Row 1 */}
      <div className="grid grid-cols-3 gap-6">
        {/* Requests per hour */}
        <div className="col-span-2 card-glass p-6">
          <div className="section-header">
            <div>
              <h3 className="section-title">Request Traffic</h3>
              <p className="section-subtitle">Requests vs blocked per hour (24h)</p>
            </div>
          </div>
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={stats.requests_per_hour}>
              <defs>
                <linearGradient id="gTotal" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#6366f1" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#6366f1" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="gBlocked" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis
                dataKey="hour"
                tickFormatter={h => `${h}:00`}
                tick={{ fill: '#64748b', fontSize: 11 }}
                axisLine={false}
                tickLine={false}
              />
              <YAxis tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
              <Tooltip content={<CustomTooltip />} />
              <Area type="monotone" dataKey="total" stroke="#6366f1" fill="url(#gTotal)" name="Total" strokeWidth={2} />
              <Area type="monotone" dataKey="blocked" stroke="#ef4444" fill="url(#gBlocked)" name="Blocked" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Attack type pie */}
        <div className="card-glass p-6">
          <h3 className="section-title mb-1">Attack Types</h3>
          <p className="section-subtitle mb-4">Distribution of threat categories</p>
          <ResponsiveContainer width="100%" height={160}>
            <PieChart>
              <Pie
                data={attackPieData}
                cx="50%"
                cy="50%"
                innerRadius={45}
                outerRadius={75}
                paddingAngle={3}
                dataKey="value"
              >
                {attackPieData.map((_, i) => (
                  <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ background: '#1e293b', border: '1px solid rgba(99,102,241,0.3)', borderRadius: 8 }}
                labelStyle={{ color: '#94a3b8' }}
              />
            </PieChart>
          </ResponsiveContainer>
          {/* Legend */}
          <div className="space-y-1.5 mt-2">
            {attackPieData.slice(0, 5).map((item, i) => (
              <div key={item.name} className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full" style={{ background: PIE_COLORS[i % PIE_COLORS.length] }} />
                  <span className="text-slate-400 capitalize">{item.name}</span>
                </div>
                <span className="text-slate-300 font-semibold">{item.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Charts Row 2 */}
      <div className="grid grid-cols-2 gap-6">
        {/* Provider distribution */}
        <div className="card-glass p-6">
          <h3 className="section-title mb-1">Provider Usage</h3>
          <p className="section-subtitle mb-4">Requests by LLM provider</p>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={providerData} layout="vertical">
              <XAxis type="number" tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis type="category" dataKey="name" tick={{ fill: '#94a3b8', fontSize: 12 }} axisLine={false} tickLine={false} width={70} />
              <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid rgba(99,102,241,0.3)', borderRadius: 8 }} />
              <Bar dataKey="value" fill="#6366f1" radius={[0, 4, 4, 0]} name="Requests" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Top threats */}
        <div className="card-glass p-6">
          <h3 className="section-title mb-1">Top Threats</h3>
          <p className="section-subtitle mb-4">Most detected attack patterns</p>
          <div className="space-y-3">
            {stats.top_threats.map((threat, i) => {
              const color = THREAT_COLORS[threat.type] || '#6b7280'
              const max = stats.top_threats[0]?.count || 1
              const pct = (threat.count / max) * 100
              return (
                <div key={threat.type}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm text-slate-300 capitalize font-medium">
                      {threat.type.replace(/_/g, ' ')}
                    </span>
                    <span className="text-sm font-bold" style={{ color }}>
                      {threat.count}
                    </span>
                  </div>
                  <div className="risk-bar">
                    <div
                      className="risk-bar-fill transition-all duration-700"
                      style={{ width: `${pct}%`, background: color }}
                    />
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      </div>

      {/* Recent Events Table */}
      <div className="card-glass p-6">
        <div className="section-header">
          <div>
            <h3 className="section-title">Recent Events</h3>
            <p className="section-subtitle">Live request log</p>
          </div>
          <span className="live-indicator">Live</span>
        </div>
        <ThreatTable events={events} maxRows={20} />
      </div>
    </div>
  )
}
