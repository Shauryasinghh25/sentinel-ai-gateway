import { Settings as SettingsIcon, Key, Server, Bell, Shield, Copy, CheckCircle } from 'lucide-react'
import { useEffect, useState } from 'react'

export default function Settings() {
  const [copied, setCopied] = useState(false)
  const [providers, setProviders] = useState<any>(null)
  
  const isDemo = import.meta.env.VITE_DEMO_MODE === 'true'
  const activeKey = import.meta.env.VITE_API_KEY || '••••••••••••••••'

  const copyKey = () => {
    if (activeKey.includes('•')) return
    navigator.clipboard.writeText(activeKey)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  useEffect(() => {
    fetch(`${import.meta.env.VITE_API_URL}/gateway/providers`)
      .then(res => res.json())
      .then(data => setProviders(data))
      .catch(err => console.error('Failed to load providers:', err))
  }, [])

  return (
    <div className="page-enter space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-3">
          <SettingsIcon className="text-indigo-400" size={28} />
          Settings
        </h1>
        <p className="text-slate-400 text-sm mt-1">Gateway configuration and API access</p>
      </div>

      <div className="grid grid-cols-2 gap-6">
        {/* API Access */}
        <div className="card-glass p-6">
          <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
            <Key size={16} className="text-indigo-400" />
            Security Auth
          </h3>

          <div className="space-y-4">
            <div>
              <label className="text-xs text-slate-400 font-medium block mb-2">
                {isDemo ? 'Demo API Key' : 'Active API Key'}
              </label>
              <div className="flex items-center gap-2">
                <code className="flex-1 bg-slate-900/80 border border-slate-700 rounded-lg px-4 py-2.5 text-sm font-mono text-green-400">
                  {activeKey}
                </code>
                {!activeKey.includes('•') && (
                  <button onClick={copyKey} className="btn-secondary p-2.5">
                    {copied ? <CheckCircle size={16} className="text-green-400" /> : <Copy size={16} />}
                  </button>
                )}
              </div>
              <p className="text-xs text-slate-500 mt-2">
                {isDemo 
                  ? 'Demo mode enabled. This key is for demonstration only.' 
                  : 'API Authentication is enabled. Use this key in X-API-Key header.'}
              </p>
            </div>

            <div>
              <label className="text-xs text-slate-400 font-medium block mb-2">Gateway Base URL</label>
              <code className="block w-full bg-slate-900/80 border border-slate-700 rounded-lg px-4 py-2.5 text-sm font-mono text-slate-300">
                {import.meta.env.VITE_API_URL || 'http://localhost:8000'}
              </code>
            </div>
          </div>
        </div>

        {/* Provider Config */}
        <div className="card-glass p-6">
          <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
            <Server size={16} className="text-indigo-400" />
            LLM Providers
          </h3>
          <div className="space-y-3">
    {[
      {
        name: 'OpenAI',
        key: 'OPENAI_API_KEY',
        configured: providers?.openai,
      },
      {
        name: 'Anthropic',
        key: 'ANTHROPIC_API_KEY',
        configured: providers?.anthropic,
      },
      {
        name: 'Google Gemini',
        key: 'GOOGLE_API_KEY',
        configured: providers?.google,
      },
      {
        name: 'Ollama',
        key: 'OLLAMA_BASE_URL',
        configured: providers?.ollama,
      },
    ].map((p) => (
      <div
        key={p.name}
        className="flex items-center justify-between py-2 border-b border-slate-700/30"
      >
        <div>
          <p className="text-sm font-medium text-slate-200">{p.name}</p>
          <p className="text-xs font-mono text-slate-500">{p.key}</p>
        </div>

        <span
          className={`text-xs font-semibold ${
            p.configured ? 'text-green-400' : 'text-slate-500'
          }`}
        >
          {p.configured ? 'configured' : 'not set'}
        </span>
      </div>
    ))}
  </div>

  <p className="text-xs text-slate-500 mt-3">
    Configure via .env file in backend directory
  </p>
</div>
        {/* Security Config */}
        <div className="card-glass p-6">
          <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
            <Shield size={16} className="text-indigo-400" />
            Security Configuration
          </h3>
          <div className="code-block text-xs">
            <div><span className="text-indigo-300">INJECTION_CONFIDENCE_THRESHOLD</span>: <span className="text-green-400">0.70</span></div>
            <div><span className="text-indigo-300">TOXICITY_THRESHOLD</span>: <span className="text-green-400">0.80</span></div>
            <div><span className="text-indigo-300">RISK_SCORE_BLOCK_THRESHOLD</span>: <span className="text-green-400">0.85</span></div>
            <div><span className="text-indigo-300">RATE_LIMIT_REQUESTS</span>: <span className="text-green-400">100</span></div>
            <div><span className="text-indigo-300">RATE_LIMIT_WINDOW_SECONDS</span>: <span className="text-green-400">60</span></div>
          </div>
        </div>

        {/* API Endpoints */}
        <div className="card-glass p-6">
          <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
            <Server size={16} className="text-indigo-400" />
            API Endpoints
          </h3>
          <div className="space-y-2">
            {[
              { method: 'POST', path: '/gateway/chat', desc: 'Main LLM proxy' },
              { method: 'POST', path: '/gateway/analyze', desc: 'Security-only check' },
              { method: 'POST', path: '/security/check/input', desc: 'Input analysis' },
              { method: 'POST', path: '/security/check/output', desc: 'Output analysis' },
              { method: 'POST', path: '/security/rag/validate', desc: 'RAG chunk validation' },
              { method: 'POST', path: '/security/mcp/validate', desc: 'Tool call security' },
              { method: 'GET', path: '/security/redteam', desc: 'Red team suite' },
              { method: 'GET', path: '/analytics/stats', desc: 'Dashboard stats' },
              { method: 'GET', path: '/metrics', desc: 'Prometheus metrics' },
            ].map(ep => (
              <div key={ep.path} className="flex items-center gap-3 py-1.5">
                <span className={`text-xs font-bold font-mono w-12 flex-shrink-0 ${ep.method === 'POST' ? 'text-blue-400' : 'text-green-400'}`}>
                  {ep.method}
                </span>
                <code className="text-xs font-mono text-slate-300 flex-1">{ep.path}</code>
                <span className="text-xs text-slate-500">{ep.desc}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
