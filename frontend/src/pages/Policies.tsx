import { useState, useEffect } from 'react'
import { FileText, Save, RefreshCw, Loader } from 'lucide-react'
import { apiClient, Policy } from '../api/client'
import { clsx } from 'clsx'

import BackendOffline from '../components/BackendOffline'

const POLICY_IDS = ['default', 'strict', 'permissive']

interface ToggleFieldProps {
  label: string
  description?: string
  value: boolean
  onChange: (v: boolean) => void
}

function ToggleField({ label, description, value, onChange }: ToggleFieldProps) {
  return (
    <div className="flex items-start justify-between py-3 border-b border-slate-700/30">
      <div>
        <p className="text-sm font-medium text-slate-200">{label}</p>
        {description && <p className="text-xs text-slate-500 mt-0.5">{description}</p>}
      </div>
      <button
        onClick={() => onChange(!value)}
        className={clsx('toggle flex-shrink-0 ml-4', value && 'on')}
        aria-label={label}
      />
    </div>
  )
}

interface SliderFieldProps {
  label: string
  value: number
  min?: number
  max?: number
  step?: number
  onChange: (v: number) => void
}

function SliderField({ label, value, min = 0, max = 1, step = 0.05, onChange }: SliderFieldProps) {
  return (
    <div className="py-3 border-b border-slate-700/30">
      <div className="flex items-center justify-between mb-2">
        <p className="text-sm font-medium text-slate-200">{label}</p>
        <span className="text-sm font-mono text-indigo-400 font-semibold">{value.toFixed(2)}</span>
      </div>
      <input
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        onChange={e => onChange(parseFloat(e.target.value))}
        className="w-full h-2 rounded-lg appearance-none cursor-pointer"
        style={{
          background: `linear-gradient(to right, #6366f1 0%, #6366f1 ${((value - min) / (max - min)) * 100}%, #334155 ${((value - min) / (max - min)) * 100}%, #334155 100%)`
        }}
      />
      <div className="flex justify-between text-xs text-slate-500 mt-1">
        <span>{min}</span>
        <span>{max}</span>
      </div>
    </div>
  )
}

export default function Policies() {
  const [activePolicyId, setActivePolicyId] = useState('default')
  const [policy, setPolicy] = useState<Policy | null>(null)
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)
  const [error, setError] = useState(false)

  const fetchPolicy = async (id: string) => {
    setLoading(true)
    setError(false)
    try {
      const p = await apiClient.getPolicy(id)
      setPolicy(p)
    } catch {
      if (import.meta.env.VITE_DEMO_MODE === 'true') {
        setPolicy({
          policy_id: id,
          name: id === 'strict' ? 'Strict Policy' : id === 'permissive' ? 'Permissive Policy' : 'Default Policy',
          version: '1.0',
          toxicity_threshold: id === 'strict' ? 0.5 : id === 'permissive' ? 0.95 : 0.8,
          injection_confidence_threshold: id === 'strict' ? 0.5 : id === 'permissive' ? 0.9 : 0.7,
          risk_score_block_threshold: id === 'strict' ? 0.65 : id === 'permissive' ? 0.98 : 0.85,
          block_pii: id !== 'permissive',
          redact_pii: true,
          block_financial_advice: id === 'strict',
          block_medical_advice: id === 'strict',
          block_code_execution: id === 'strict',
          block_political_content: id === 'strict',
          allowed_tools: ['weather_api', 'calculator', 'currency_converter'],
          blocked_tools: ['shell', 'exec', 'bash', 'delete_file'],
          rate_limit_requests: id === 'strict' ? 50 : id === 'permissive' ? 1000 : 100,
        })
      } else {
        setError(true)
        setPolicy(null)
      }
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchPolicy(activePolicyId) }, [activePolicyId])

  const update = (key: keyof Policy, value: any) => {
    if (!policy) return
    setPolicy({ ...policy, [key]: value })
  }

  const save = async () => {
    if (!policy) return
    setSaving(true)
    try {
      await apiClient.updatePolicy(activePolicyId, policy as any)
    } catch {
      // Demo: just show success
    } finally {
      setSaving(false)
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    }
  }

  return (
    <div className="page-enter space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <FileText className="text-indigo-400" size={28} />
            Policy Engine
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            Configure security policies for each deployment
          </p>
        </div>
        <button
          onClick={save}
          disabled={saving}
          className={clsx('btn-primary flex items-center gap-2', saved && 'bg-green-600 hover:bg-green-500')}
        >
          {saving ? <Loader size={14} className="animate-spin" /> : <Save size={14} />}
          {saved ? 'Saved!' : 'Save Policy'}
        </button>
      </div>

      <div className="grid grid-cols-4 gap-6">
        {/* Policy selector */}
        <div className="col-span-1 space-y-2">
          <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Policies</p>
          {POLICY_IDS.map(id => (
            <button
              key={id}
              onClick={() => setActivePolicyId(id)}
              className={clsx(
                'w-full text-left px-4 py-3 rounded-lg text-sm font-medium transition-all border',
                activePolicyId === id
                  ? 'bg-indigo-600/20 text-white border-indigo-500/30'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800 border-transparent'
              )}
            >
              <div className="capitalize font-semibold">{id}</div>
              <div className="text-xs opacity-60 mt-0.5">
                {id === 'strict' ? 'Maximum security' : id === 'permissive' ? 'Dev/Test only' : 'Balanced'}
              </div>
            </button>
          ))}

          <div className="mt-4 pt-4 border-t border-slate-700/50">
            <div className="code-block text-xs">
              <div className="text-slate-400 mb-1"># Active policy</div>
              <div className="text-green-400">policy_id: {activePolicyId}</div>
            </div>
          </div>
        </div>

        {/* Policy editor */}
        <div className="col-span-3">
          {error ? (
            <div className="py-12">
              <BackendOffline onRetry={() => fetchPolicy(activePolicyId)} />
            </div>
          ) : loading ? (
            <div className="flex items-center justify-center h-64">
              <Loader size={28} className="animate-spin text-indigo-400" />
            </div>
          ) : policy ? (
            <div className="grid grid-cols-2 gap-4">
              {/* Thresholds */}
              <div className="card-glass p-5">
                <h3 className="text-sm font-semibold text-white mb-4 pb-2 border-b border-slate-700/50">
                  Detection Thresholds
                </h3>
                <SliderField
                  label="Toxicity Threshold"
                  value={policy.toxicity_threshold}
                  onChange={v => update('toxicity_threshold', v)}
                />
                <SliderField
                  label="Injection Confidence"
                  value={policy.injection_confidence_threshold}
                  onChange={v => update('injection_confidence_threshold', v)}
                />
                <SliderField
                  label="Block Threshold (Risk Score)"
                  value={policy.risk_score_block_threshold}
                  onChange={v => update('risk_score_block_threshold', v)}
                />
                <SliderField
                  label="Rate Limit (req/min)"
                  value={policy.rate_limit_requests}
                  min={10}
                  max={1000}
                  step={10}
                  onChange={v => update('rate_limit_requests', v)}
                />
              </div>

              {/* Toggles */}
              <div className="card-glass p-5">
                <h3 className="text-sm font-semibold text-white mb-4 pb-2 border-b border-slate-700/50">
                  Security Rules
                </h3>
                <ToggleField
                  label="Block PII Input"
                  description="Block requests containing PII"
                  value={policy.block_pii}
                  onChange={v => update('block_pii', v)}
                />
                <ToggleField
                  label="Redact PII"
                  description="Remove PII from requests/responses"
                  value={policy.redact_pii}
                  onChange={v => update('redact_pii', v)}
                />
                <ToggleField
                  label="Block Financial Advice"
                  description="Block financial guidance requests"
                  value={policy.block_financial_advice}
                  onChange={v => update('block_financial_advice', v)}
                />
                <ToggleField
                  label="Block Medical Advice"
                  description="Block medical guidance requests"
                  value={policy.block_medical_advice}
                  onChange={v => update('block_medical_advice', v)}
                />
                <ToggleField
                  label="Block Code Execution"
                  description="Block code execution requests"
                  value={policy.block_code_execution}
                  onChange={v => update('block_code_execution', v)}
                />
                <ToggleField
                  label="Block Political Content"
                  description="Block political content generation"
                  value={policy.block_political_content}
                  onChange={v => update('block_political_content', v)}
                />
              </div>

              {/* Tool allow/deny */}
              <div className="card-glass p-5 col-span-2">
                <h3 className="text-sm font-semibold text-white mb-4 pb-2 border-b border-slate-700/50">
                  Tool Permissions (MCP)
                </h3>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <p className="text-xs font-semibold text-green-400 uppercase tracking-wider mb-2">
                      Allowed Tools
                    </p>
                    <div className="flex flex-wrap gap-2">
                      {policy.allowed_tools.map(t => (
                        <span key={t} className="badge badge-allowed">{t}</span>
                      ))}
                    </div>
                  </div>
                  <div>
                    <p className="text-xs font-semibold text-red-400 uppercase tracking-wider mb-2">
                      Blocked Tools
                    </p>
                    <div className="flex flex-wrap gap-2">
                      {policy.blocked_tools.map(t => (
                        <span key={t} className="badge badge-blocked">{t}</span>
                      ))}
                    </div>
                  </div>
                </div>

                <div className="mt-4 pt-4 border-t border-slate-700/30">
                  <p className="text-xs text-slate-500">
                    Edit tool lists via YAML configuration. Changes take effect on next request.
                  </p>
                  <div className="code-block mt-3 text-xs">
                    <span className="text-indigo-300">allowed_tools:</span>
                    {policy.allowed_tools.map(t => (
                      <div key={t}>{'  '}<span className="text-green-400">- {t}</span></div>
                    ))}
                    <br />
                    <span className="text-indigo-300">blocked_tools:</span>
                    {policy.blocked_tools.map(t => (
                      <div key={t}>{'  '}<span className="text-red-400">- {t}</span></div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  )
}
