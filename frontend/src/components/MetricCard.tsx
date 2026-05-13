import { LucideIcon, TrendingUp, TrendingDown, Minus } from 'lucide-react'
import { clsx } from 'clsx'

interface MetricCardProps {
  title: string
  value: string | number
  subtitle?: string
  icon: LucideIcon
  trend?: 'up' | 'down' | 'neutral'
  trendValue?: string
  accent?: 'indigo' | 'red' | 'green' | 'orange' | 'yellow'
  large?: boolean
}

const accentColors = {
  indigo: 'text-indigo-400 bg-indigo-500/10 border-indigo-500/20',
  red:    'text-red-400 bg-red-500/10 border-red-500/20',
  green:  'text-green-400 bg-green-500/10 border-green-500/20',
  orange: 'text-orange-400 bg-orange-500/10 border-orange-500/20',
  yellow: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
}

const trendConfig = {
  up:      { icon: TrendingUp,   color: 'text-red-400'   },
  down:    { icon: TrendingDown, color: 'text-green-400' },
  neutral: { icon: Minus,        color: 'text-slate-400' },
}

export default function MetricCard({
  title, value, subtitle, icon: Icon,
  trend = 'neutral', trendValue, accent = 'indigo', large = false
}: MetricCardProps) {
  const TrendIcon = trendConfig[trend].icon
  const trendColor = trendConfig[trend].color

  return (
    <div className={clsx(
      'metric-card group',
      large && 'col-span-2'
    )}>
      <div className="flex items-start justify-between mb-4">
        <div className={clsx(
          'w-10 h-10 rounded-xl flex items-center justify-center border transition-all duration-300',
          accentColors[accent],
          'group-hover:scale-110'
        )}>
          <Icon size={20} />
        </div>
        {trendValue && (
          <div className={clsx('flex items-center gap-1 text-xs font-medium', trendColor)}>
            <TrendIcon size={12} />
            {trendValue}
          </div>
        )}
      </div>

      <p className="text-3xl font-bold text-white tracking-tight mb-1">
        {value}
      </p>
      <p className="text-sm font-medium text-slate-300">{title}</p>
      {subtitle && (
        <p className="text-xs text-slate-500 mt-1">{subtitle}</p>
      )}
    </div>
  )
}
