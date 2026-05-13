import { useEffect, useState } from 'react'
import { BarChart3 } from 'lucide-react'
import {
  LineChart, Line, BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, AreaChart, Area, Cell
} from 'recharts'
import { apiClient, DashboardStats } from '../api/client'
import BackendOffline from '../components/BackendOffline'

const MODEL_COLORS = ['#6366f1', '#06b6d4', '#8b5cf6', '#10b981', '#f97316']

function getDemoStats(): DashboardStats {
  return {
    total_requests: 2847, blocked_requests: 438, allowed_requests: 2247,
    flagged_requests: 102, sanitized_requests: 60, block_rate: 0.154,
    avg_risk_score: 0.243, avg_latency_ms: 187.4, total_tokens: 1_284_930,
    attack_breakdown: { jailbreak: 189, prompt_injection: 134, pii_leakage: 67, toxicity: 28 },
    provider_breakdown: { openai: 1842, anthropic: 634, google: 271, ollama: 100 },
    model_breakdown: { 'gpt-4o-mini': 1200, 'gpt-4o': 642, 'claude-3-haiku': 634, 'gemini-1.5-flash': 271 },
    requests_per_hour: Array.from({ length: 24 }, (_, h) => ({
      hour: h, total: Math.floor(Math.random() * 180 + 40), blocked: Math.floor(Math.random() * 40 + 5),
      avg_latency_ms: 180 + Math.random() * 20
    })),
    top_threats: [],
  }
}

export default function Analytics() {
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [hours, setHours] = useState(24)
  const [error, setError] = useState(false)

  const load = () => {
    setError(false)
    apiClient.getStats(hours)
      .then(setStats)
      .catch(() => {
        if (import.meta.env.VITE_DEMO_MODE === 'true') {
          setStats(getDemoStats())
        } else {
          setError(true)
        }
      })
  }

  useEffect(() => {
    load()
  }, [hours])

  if (error) {
    return (
      <div className="page-enter py-12">
        <BackendOffline onRetry={load} />
      </div>
    )
  }

  if (!stats) return null

  const modelData = Object.entries(stats.model_breakdown).map(([name, value]) => ({ name, value }))
  const latencyData = stats.requests_per_hour.map(h => ({
    hour: h.hour,
    avg_latency: (h as any).avg_latency_ms || 0
  }))

  return (
    <div className="page-enter space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <BarChart3 className="text-indigo-400" size={28} />
            Analytics
          </h1>
          <p className="text-slate-400 text-sm mt-1">Detailed request metrics and performance</p>
        </div>
        <div className="flex gap-2">
          {[6, 24, 48, 168].map(h => (
            <button
              key={h}
              onClick={() => setHours(h)}
              className={`px-3 py-1.5 rounded-lg text-sm transition-all ${hours === h ? 'bg-indigo-600 text-white' : 'bg-slate-800 text-slate-400'}`}
            >
              {h < 24 ? `${h}h` : h === 24 ? '24h' : h === 48 ? '2d' : '7d'}
            </button>
          ))}
        </div>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'Total Requests', value: stats.total_requests.toLocaleString(), color: 'text-indigo-400' },
          { label: 'Block Rate', value: `${(stats.block_rate * 100).toFixed(1)}%`, color: 'text-red-400' },
          { label: 'Avg Latency', value: `${stats.avg_latency_ms.toFixed(0)}ms`, color: 'text-green-400' },
          { label: 'Total Tokens', value: `${(stats.total_tokens / 1000).toFixed(0)}K`, color: 'text-yellow-400' },
        ].map(kpi => (
          <div key={kpi.label} className="metric-card">
            <p className={`text-2xl font-bold ${kpi.color}`}>{kpi.value}</p>
            <p className="text-sm text-slate-400 mt-1">{kpi.label}</p>
          </div>
        ))}
      </div>

      {/* Latency over time */}
      <div className="card-glass p-6">
        <h3 className="section-title mb-1">Latency Over Time</h3>
        <p className="section-subtitle mb-5">Average response latency per hour</p>
        <ResponsiveContainer width="100%" height={220}>
          <LineChart data={latencyData}>
            <XAxis dataKey="hour" tickFormatter={h => `${h}:00`} tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
            <YAxis tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} unit="ms" />
            <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid rgba(99,102,241,0.3)', borderRadius: 8 }} />
            <Line type="monotone" dataKey="avg_latency" stroke="#6366f1" strokeWidth={2} dot={false} name="Latency (ms)" />
          </LineChart>
        </ResponsiveContainer>
      </div>

      <div className="grid grid-cols-2 gap-6">
        {/* Model usage */}
        <div className="card-glass p-6">
          <h3 className="section-title mb-1">Model Usage</h3>
          <p className="section-subtitle mb-4">Requests by model</p>
          <div className="space-y-3">
            {modelData.map((m, i) => {
              const max = modelData[0]?.value || 1
              const pct = (m.value / max) * 100
              return (
                <div key={m.name}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm text-slate-300 font-mono">{m.name}</span>
                    <span className="text-sm font-bold text-white">{m.value.toLocaleString()}</span>
                  </div>
                  <div className="risk-bar">
                    <div
                      className="risk-bar-fill transition-all duration-700"
                      style={{ width: `${pct}%`, background: MODEL_COLORS[i % MODEL_COLORS.length] }}
                    />
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* Request volume by hour */}
        <div className="card-glass p-6">
          <h3 className="section-title mb-1">Hourly Volume</h3>
          <p className="section-subtitle mb-4">Allowed vs blocked per hour</p>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={stats.requests_per_hour} barGap={2}>
              <XAxis dataKey="hour" tickFormatter={h => `${h}`} tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid rgba(99,102,241,0.3)', borderRadius: 8 }} />
              <Bar dataKey="total" fill="#6366f1" radius={[2, 2, 0, 0]} name="Total" />
              <Bar dataKey="blocked" fill="#ef4444" radius={[2, 2, 0, 0]} name="Blocked" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  )
}
