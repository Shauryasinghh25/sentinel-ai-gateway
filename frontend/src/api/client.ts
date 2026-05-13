import axios from 'axios'

const BASE_URL = import.meta.env.VITE_API_URL
const API_KEY = import.meta.env.VITE_API_KEY

const api = axios.create({
  baseURL: BASE_URL,
  headers: {
    'X-API-Key': API_KEY,
    'Content-Type': 'application/json',
  },
})

// ── Types ────────────────────────────────────────────────────────────────────

export interface DashboardStats {
  total_requests: number
  blocked_requests: number
  allowed_requests: number
  flagged_requests: number
  sanitized_requests: number
  block_rate: number
  avg_risk_score: number
  avg_latency_ms: number
  total_tokens: number
  attack_breakdown: Record<string, number>
  provider_breakdown: Record<string, number>
  model_breakdown: Record<string, number>
  requests_per_hour: { hour: number; total: number; blocked: number }[]
  top_threats: { type: string; count: number }[]
}

export interface RequestEvent {
  event_id: string
  timestamp: string
  request_id: string
  provider: string
  model: string
  action: 'allowed' | 'blocked' | 'sanitized' | 'flagged'
  risk_score: number
  attack_types: string[]
  latency_ms: number
  tokens: number
  policy_id: string
}

export interface SecurityCheckResult {
  action: string
  risk_score: number
  risk_level: string
  violations: {
    guard: string
    attack_type: string
    confidence: number
    message: string
    risk_level: string
  }[]
  sanitized_text?: string
  latency_ms: number
}

export interface Policy {
  policy_id: string
  name: string
  version: string
  toxicity_threshold: number
  injection_confidence_threshold: number
  risk_score_block_threshold: number
  block_pii: boolean
  redact_pii: boolean
  block_financial_advice: boolean
  block_medical_advice: boolean
  block_code_execution: boolean
  block_political_content: boolean
  allowed_tools: string[]
  blocked_tools: string[]
  rate_limit_requests: number
}

export interface ThreatEvent {
  timestamp: string
  attack_type: string
  risk_score: number
  provider: string
  model: string
}

export interface RedTeamResult {
  category: string
  description: string
  input_text: string
  expected_blocked: boolean
  was_blocked: boolean
  risk_score: number
  risk_level: string
  passed: boolean
  primary_attack: string | null
}

export interface AgentAnalyzeResponse {
  request_id: string | null
  action: string
  risk_score: number
  risk_level: string
  should_block: boolean
  violations: {
    guard: string
    attack_type: string
    confidence: number
    message: string
    risk_level: string
    metadata: Record<string, any>
  }[]
  sanitized_text: string | null
  pipeline_findings: Record<string, any>
  explanation: string
  recommendations: string[]
  node_latencies: Record<string, number>
  total_latency_ms: number
}

export interface GraphInfo {
  graph_name: string
  version: string
  architecture: string
  layers: {
    '1_core_detection': string[]
    '2_evaluation': string[]
    '3_explainer': string[]
  }
  nodes: { id: string; type: string; layer: number; description: string }[]
  edges: { from: string; to: string }[]
  evaluation_pipeline_active: string[]
  description: string
}

// ── API Calls ─────────────────────────────────────────────────────────────────

export const apiClient = {
  // Analytics
  getStats: (hours = 24): Promise<DashboardStats> =>
    api.get(`/analytics/stats?hours=${hours}`).then(r => r.data),

  getEvents: (limit = 100): Promise<{ total: number; events: RequestEvent[] }> =>
    api.get(`/analytics/events?limit=${limit}`).then(r => r.data),

  getThreats: (hours = 24): Promise<{ total_threats: number; timeline: ThreatEvent[] }> =>
    api.get(`/analytics/threats?hours=${hours}`).then(r => r.data),

  // Security
  checkInput: (text: string): Promise<SecurityCheckResult> =>
    api.post('/security/check/input', { text }).then(r => r.data),

  checkOutput: (text: string): Promise<SecurityCheckResult> =>
    api.post('/security/check/output', { text }).then(r => r.data),

  runRedTeam: (): Promise<{
    passed: number; failed: number; total: number; pass_rate: number;
    results: RedTeamResult[]
  }> =>
    api.get('/security/redteam').then(r => r.data),

  // Policy
  listPolicies: () => api.get('/policy/list').then(r => r.data),
  getPolicy: (id: string): Promise<Policy> => api.get(`/policy/${id}`).then(r => r.data),
  updatePolicy: (id: string, updates: Partial<Policy>) =>
    api.put(`/policy/${id}`, { updates }).then(r => r.data),

  // Health
  getHealth: () => api.get('/gateway/health').then(r => r.data),

  // LangGraph Agent
  analyzeAgent: (text: string, policyId = 'default', context?: any): Promise<AgentAnalyzeResponse> =>
    api.post('/agent/analyze', { text, policy_id: policyId, context }).then(r => r.data),
  
  getGraphInfo: (): Promise<GraphInfo> =>
    api.get('/agent/graph/info').then(r => r.data),
}
