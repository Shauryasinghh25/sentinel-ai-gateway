import { NavLink } from 'react-router-dom'
import {
  Shield, LayoutDashboard, AlertTriangle,
  BarChart3, Settings, Zap, FileText,
  ChevronRight, Activity, Bot
} from 'lucide-react'
import { clsx } from 'clsx'

const navItems = [
  { to: '/',          icon: LayoutDashboard, label: 'Dashboard',  end: true },
  { to: '/agent',     icon: Bot,             label: 'Security Agent'      },
  { to: '/threats',   icon: AlertTriangle,   label: 'Threats'             },
  { to: '/analytics', icon: BarChart3,       label: 'Analytics'           },
  { to: '/scanner',   icon: Zap,             label: 'Live Scanner'        },
  { to: '/redteam',   icon: Activity,        label: 'Red Team'            },
  { to: '/policies',  icon: FileText,        label: 'Policies'            },
  { to: '/settings',  icon: Settings,        label: 'Settings'            },
]

export default function Sidebar() {
  return (
    <aside className="fixed left-0 top-0 h-screen w-64 bg-slate-900/95 backdrop-blur-md border-r border-indigo-500/10 flex flex-col z-50">
      {/* Logo */}
      <div className="p-6 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-indigo-600 flex items-center justify-center glow-indigo">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="font-bold text-white text-lg leading-tight tracking-tight">
              SentinelAI
            </h1>
            <p className="text-xs text-slate-400 font-medium">Security Gateway</p>
          </div>
        </div>
      </div>

      {/* Live status */}
      <div className="px-4 py-3 border-b border-slate-800/50">
        <div className="flex items-center justify-between">
          <span className="live-indicator">Live</span>
          <span className="text-xs text-slate-500 font-mono">v1.0.0</span>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
        {navItems.map(({ to, icon: Icon, label, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) =>
              clsx(
                'flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm font-medium transition-all duration-200 group',
                isActive
                  ? 'text-white bg-indigo-600/20 border border-indigo-500/30'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800'
              )
            }
          >
            {({ isActive }) => (
              <>
                <Icon className={clsx(
                  'w-4.5 h-4.5 transition-colors',
                  isActive ? 'text-indigo-400' : 'text-slate-500 group-hover:text-slate-300'
                )} size={18} />
                <span>{label}</span>
                {isActive && (
                  <ChevronRight className="w-3 h-3 text-indigo-400 ml-auto" />
                )}
              </>
            )}
          </NavLink>
        ))}
      </nav>

      {/* Footer */}
      <div className="p-4 border-t border-slate-800">
        <div className="rounded-lg bg-slate-800/50 p-3 border border-slate-700/50">
          <p className="text-xs text-slate-400 font-medium">Security Status</p>
          <div className="flex items-center gap-2 mt-2">
            <span className="status-dot online" />
            <span className="text-xs text-green-400 font-medium">All systems operational</span>
          </div>
        </div>
      </div>
    </aside>
  )
}
