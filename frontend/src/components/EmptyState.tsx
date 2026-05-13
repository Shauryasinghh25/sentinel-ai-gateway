import { LucideIcon, Search } from 'lucide-react'

interface EmptyStateProps {
  title: string
  message: string
  icon?: LucideIcon
}

export default function EmptyState({ 
  title, 
  message, 
  icon: Icon = Search 
}: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center py-20 px-4 text-center">
      <div className="w-16 h-16 bg-slate-800/50 rounded-full flex items-center justify-center mb-4">
        <Icon size={32} className="text-slate-500" />
      </div>
      <h2 className="text-lg font-semibold text-slate-300 mb-1">{title}</h2>
      <p className="text-slate-500 max-w-xs text-sm">{message}</p>
    </div>
  )
}
