import { clsx } from 'clsx'
import { RequestEvent } from '../api/client'
import { AlertOctagon, CheckCircle, ShieldAlert, Eye } from 'lucide-react'

interface ThreatTableProps {
  events: RequestEvent[]
  maxRows?: number
}

const actionConfig: Record<string, { label: string; cls: string; icon: any }> = {
  blocked:   { label: 'Blocked',   cls: 'badge-blocked',   icon: AlertOctagon },
  allowed:   { label: 'Allowed',   cls: 'badge-allowed',   icon: CheckCircle  },
  sanitized: { label: 'Sanitized', cls: 'badge-sanitized', icon: ShieldAlert  },
  flagged:   { label: 'Flagged',   cls: 'badge-flagged',   icon: Eye          },
}

function getRiskColor(score: number) {
  if (score >= 0.9) return 'threat-critical'
  if (score >= 0.75) return 'threat-high'
  if (score >= 0.6) return 'threat-medium'
  if (score >= 0.3) return 'threat-low'
  return 'threat-none'
}

function getRiskBg(score: number) {
  if (score >= 0.9) return 'bg-red-500'
  if (score >= 0.75) return 'bg-orange-500'
  if (score >= 0.6) return 'bg-yellow-500'
  if (score >= 0.3) return 'bg-green-500'
  return 'bg-slate-600'
}

function formatTime(ts: string) {
  const d = new Date(ts)
  return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

function formatAttackType(at: string) {
  return at.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
}

export default function ThreatTable({ events, maxRows = 50 }: ThreatTableProps) {
  const rows = events.slice(0, maxRows)

  if (rows.length === 0) {
    return (
      <div className="flex items-center justify-center h-32 text-slate-500 text-sm">
        No events yet. Waiting for requests...
      </div>
    )
  }

  return (
    <div className="overflow-x-auto">
      <table className="data-table">
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Action</th>
            <th>Risk Score</th>
            <th>Attack Type</th>
            <th>Provider</th>
            <th>Model</th>
            <th>Latency</th>
            <th>Tokens</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((event) => {
            const cfg = actionConfig[event.action] || actionConfig.allowed
            const ActionIcon = cfg.icon
            const riskColor = getRiskColor(event.risk_score)
            const riskBg = getRiskBg(event.risk_score)

            return (
              <tr key={event.event_id} className="group">
                <td className="font-mono text-xs text-slate-400">
                  {formatTime(event.timestamp)}
                </td>
                <td>
                  <span className={clsx('badge flex items-center gap-1.5 w-fit', cfg.cls)}>
                    <ActionIcon size={11} />
                    {cfg.label}
                  </span>
                </td>
                <td>
                  <div className="flex items-center gap-2">
                    <span className={clsx('text-sm font-semibold font-mono', riskColor)}>
                      {(event.risk_score * 100).toFixed(0)}%
                    </span>
                    <div className="risk-bar w-16">
                      <div
                        className={clsx('risk-bar-fill', riskBg)}
                        style={{ width: `${event.risk_score * 100}%` }}
                      />
                    </div>
                  </div>
                </td>
                <td>
                  {event.attack_types.length > 0 ? (
                    <div className="flex flex-wrap gap-1">
                      {event.attack_types.slice(0, 2).map(at => (
                        <span key={at} className="text-xs px-1.5 py-0.5 rounded bg-slate-700/60 text-slate-300 font-medium">
                          {formatAttackType(at)}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <span className="text-slate-600 text-xs">—</span>
                  )}
                </td>
                <td className="text-slate-300 text-xs font-medium capitalize">{event.provider}</td>
                <td className="font-mono text-xs text-slate-400">{event.model}</td>
                <td className="font-mono text-xs text-slate-400">{event.latency_ms.toFixed(0)}ms</td>
                <td className="font-mono text-xs text-slate-400">{event.tokens.toLocaleString()}</td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
