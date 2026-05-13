import { AlertCircle, RefreshCw } from 'lucide-react'

interface BackendOfflineProps {
  title?: string
  message?: string
  onRetry?: () => void
}

export default function BackendOffline({ 
  title = "Backend Service Unavailable", 
  message = "We couldn't connect to the security gateway. Please ensure the backend server is running.",
  onRetry 
}: BackendOfflineProps) {
  return (
    <div className="flex flex-col items-center justify-center py-20 px-4 text-center card-glass bg-red-500/5 border-red-500/20">
      <div className="w-16 h-16 bg-red-500/10 rounded-full flex items-center justify-center mb-4">
        <AlertCircle size={32} className="text-red-400" />
      </div>
      <h2 className="text-xl font-bold text-white mb-2">{title}</h2>
      <p className="text-slate-400 max-w-md mb-6">{message}</p>
      {onRetry && (
        <button 
          onClick={onRetry}
          className="btn-secondary flex items-center gap-2"
        >
          <RefreshCw size={16} />
          Retry Connection
        </button>
      )}
    </div>
  )
}
