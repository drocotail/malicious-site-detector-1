import axios from 'axios'

const api = axios.create({ baseURL: '' })

api.interceptors.request.use((config) => {
  if (typeof window !== 'undefined') {
    const token = localStorage.getItem('token')
    if (token) config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// 401 응답 → 사용자 토큰 삭제 후 로그인 페이지로 이동
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error?.response?.status === 401 && typeof window !== 'undefined') {
      localStorage.removeItem('token')
      localStorage.removeItem('nickname')
      window.location.href = '/auth/login'
      return new Promise(() => {})
    }
    return Promise.reject(error)
  },
)

export function extractError(err: unknown, fallback: string): string {
  const axiosErr = err as { response?: { data?: { detail?: unknown } } }
  const detail = axiosErr?.response?.data?.detail
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail) && detail.length > 0) {
    const first = detail[0] as { msg?: string }
    return first?.msg ?? fallback
  }
  return fallback
}

// risk_level (Korean) → English verdict key
export function toVerdict(riskLevel: string): 'safe' | 'suspicious' | 'dangerous' {
  if (riskLevel === '위험') return 'dangerous'
  if (riskLevel === '주의') return 'suspicious'
  return 'safe'
}

// Backend ScanResponse shape
export interface ScanResult {
  input_url: string
  normalized_url: string
  is_shortened: boolean
  expanded_url: string | null
  risk_level: string        // '위험' | '주의' | '낮음'
  risk_score: number
  decision_type: string
  final_reason: string
  features: Record<string, unknown>
  rule_info: Record<string, unknown>
  api_results: Record<string, unknown>
  ai_results: Record<string, unknown>
}

// /api/sites endpoint (PhishingSite model)
export interface Threat {
  id: number
  url: string
  domain: string
  category: string | null
  notes: string | null
  registered_at: string
}

// /api/scan/history endpoint
export interface ScanRecord {
  id: number
  url: string
  domain: string
  verdict: string   // Korean: '위험' | '주의' | '낮음'
  risk_score: number
  reason: string
  scanned_at: string
}

// /api/scan/stats endpoint
export interface Stats {
  total_scans: number
  dangerous_detected: number
  suspicious_detected: number
  db_entries: number
}

export const scanUrl = async (url: string): Promise<ScanResult> => {
  const { data } = await api.post('/api/scan', { url })
  return data
}

export const reportUrl = async (url: string, title: string): Promise<{ message: string }> => {
  const { data } = await api.post('/api/reports', { url, title, description: '' })
  return data
}

export const getRecentThreats = async (): Promise<Threat[]> => {
  const { data } = await api.get('/api/sites')
  return data
}

export const getStats = async (): Promise<Stats> => {
  const { data } = await api.get('/api/scan/stats')
  return data
}

export const getScanHistory = async (): Promise<ScanRecord[]> => {
  const { data } = await api.get('/api/scan/history')
  return data
}

// Posts
export interface Post {
  id: number
  title: string
  content: string
  user_id: number
  author_nickname: string
  view_count: number
  created_at: string
  updated_at: string | null
}

export const getPosts = async (skip = 0, limit = 20): Promise<Post[]> => {
  const { data } = await api.get(`/api/posts?skip=${skip}&limit=${limit}`)
  return data
}

export const getPost = async (id: number): Promise<Post> => {
  const { data } = await api.get(`/api/posts/${id}`)
  return data
}

export const createPost = async (title: string, content: string): Promise<Post> => {
  const { data } = await api.post('/api/posts', { title, content })
  return data
}

export const updatePost = async (id: number, title: string, content: string): Promise<Post> => {
  const { data } = await api.put(`/api/posts/${id}`, { title, content })
  return data
}

export const deletePost = async (id: number): Promise<void> => {
  await api.delete(`/api/posts/${id}`)
}

export const login = async (email: string, password: string): Promise<string> => {
  const { data } = await api.post('/api/auth/login', { email, password })
  return data.access_token
}

export const register = async (
  email: string,
  password: string,
  nickname: string,
): Promise<{ email: string; requires_verification: boolean }> => {
  const { data } = await api.post('/api/auth/register', { email, password, nickname })
  return data
}

export const verifyEmail = async (email: string, code: string): Promise<string> => {
  const { data } = await api.post('/api/auth/verify-email', { email, code })
  return data.access_token
}

export const resendCode = async (email: string): Promise<{ message: string }> => {
  const { data } = await api.post('/api/auth/resend-code', { email })
  return data
}
