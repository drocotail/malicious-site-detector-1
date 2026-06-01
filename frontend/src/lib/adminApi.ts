import axios from 'axios'

const adminApi = axios.create({ baseURL: '' })

adminApi.interceptors.request.use((config) => {
  if (typeof window !== 'undefined') {
    const token = localStorage.getItem('admin_token')
    if (token) config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// 401 응답 → 어드민 토큰 삭제 후 로그인 페이지로 이동
adminApi.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error?.response?.status === 401 && typeof window !== 'undefined') {
      localStorage.removeItem('admin_token')
      window.location.href = '/admin/login'
      // 페이지가 이동 중이므로 절대 settle되지 않는 Promise를 반환해 에러 오버레이를 막는다
      return new Promise(() => {})
    }
    return Promise.reject(error)
  },
)

export function extractAdminError(err: unknown, fallback: string): string {
  const e = err as { response?: { data?: { detail?: unknown } } }
  const detail = e?.response?.data?.detail
  if (typeof detail === 'string') return detail
  return fallback
}

// ── Types ─────────────────────────────────────────────────────────────────

export interface AdminStats {
  total_scans: number
  dangerous: number
  suspicious: number
  safe: number
  total_sites: number
  confirmed_phishing: number
  total_users: number
  blocked_users: number
  pending_reports: number
  total_posts: number
}

export interface AdminScan {
  id: number
  user_id: number | null
  url: string
  domain: string
  verdict: string
  risk_score: number
  threat_types: string[]
  scanned_at: string
}

export interface AdminSite {
  id: number
  url: string
  domain: string
  category: string
  source: string
  threat_types: string[]
  created_at: string
  confirmed_at: string | null
}

export interface AdminUser {
  id: number
  email: string
  nickname: string | null
  is_blocked: boolean
  scan_count: number
  created_at: string
}

export interface AdminPost {
  id: number
  title: string
  user_id: number
  author_nickname: string
  view_count: number
  created_at: string
}

export interface AdminReport {
  id: number
  url: string
  domain: string
  description: string | null
  user_id: number | null
  reporter_nickname: string | null
  status: 'pending' | 'approved' | 'rejected'
  reviewed_at: string | null
  created_at: string
}

// ── Auth ──────────────────────────────────────────────────────────────────

export const adminLogin = async (email: string, password: string): Promise<{ token: string; name: string }> => {
  const { data } = await adminApi.post('/api/admin/login', { email, password })
  return { token: data.access_token, name: data.name }
}

export const adminSetup = async (email: string, password: string, name: string): Promise<string> => {
  const { data } = await adminApi.post('/api/admin/setup', { email, password, name })
  return data.message
}

// ── Stats ─────────────────────────────────────────────────────────────────

export const getAdminStats = async (): Promise<AdminStats> => {
  const { data } = await adminApi.get('/api/admin/stats')
  return data
}

// ── Reports ───────────────────────────────────────────────────────────────

export const getAdminReports = async (statusFilter = 'pending', skip = 0, limit = 50): Promise<AdminReport[]> => {
  const { data } = await adminApi.get(`/api/admin/reports?status_filter=${statusFilter}&skip=${skip}&limit=${limit}`)
  return data
}

export const reviewReport = async (id: number, action: 'approve' | 'reject'): Promise<{ message: string }> => {
  const { data } = await adminApi.patch(`/api/admin/reports/${id}/review`, { action })
  return data
}

// ── Users ─────────────────────────────────────────────────────────────────

export const getAdminUsers = async (skip = 0, limit = 50): Promise<AdminUser[]> => {
  const { data } = await adminApi.get(`/api/admin/users?skip=${skip}&limit=${limit}`)
  return data
}

export const blockUser = async (id: number): Promise<{ message: string }> => {
  const { data } = await adminApi.patch(`/api/admin/users/${id}/block`)
  return data
}

export const unblockUser = async (id: number): Promise<{ message: string }> => {
  const { data } = await adminApi.patch(`/api/admin/users/${id}/unblock`)
  return data
}

// ── Sites ─────────────────────────────────────────────────────────────────

export const getAdminSites = async (skip = 0, limit = 50): Promise<AdminSite[]> => {
  const { data } = await adminApi.get(`/api/admin/sites?skip=${skip}&limit=${limit}`)
  return data
}

export const addAdminSite = async (payload: {
  url: string; domain: string; category: string; threat_types: string[]
}): Promise<void> => {
  await adminApi.post('/api/admin/sites', payload)
}

export const updateAdminSite = async (id: number, category: string): Promise<void> => {
  await adminApi.patch(`/api/admin/sites/${id}`, { category })
}

export const deleteAdminSite = async (id: number): Promise<void> => {
  await adminApi.delete(`/api/admin/sites/${id}`)
}

// ── Scans ─────────────────────────────────────────────────────────────────

export const getAdminScans = async (skip = 0, limit = 50): Promise<AdminScan[]> => {
  const { data } = await adminApi.get(`/api/admin/scans?skip=${skip}&limit=${limit}`)
  return data
}

// ── Posts ─────────────────────────────────────────────────────────────────

export const getAdminPosts = async (skip = 0, limit = 50): Promise<AdminPost[]> => {
  const { data } = await adminApi.get(`/api/admin/posts?skip=${skip}&limit=${limit}`)
  return data
}

export const deleteAdminPost = async (id: number): Promise<void> => {
  await adminApi.delete(`/api/admin/posts/${id}`)
}
