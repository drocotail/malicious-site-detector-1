'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'
import { adminLogin, adminSetup, extractAdminError } from '@/lib/adminApi'

export default function AdminLoginPage() {
  const router = useRouter()
  const [tab, setTab] = useState<'login' | 'setup'>('login')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [name, setName] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const { token } = await adminLogin(email, password)
      localStorage.setItem('admin_token', token)
      router.replace('/admin')
    } catch (err) {
      setError(extractAdminError(err, '로그인에 실패했습니다'))
    } finally {
      setLoading(false)
    }
  }

  const handleSetup = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const msg = await adminSetup(email, password, name)
      alert(msg)
      setTab('login')
    } catch (err) {
      setError(extractAdminError(err, '계정 생성에 실패했습니다'))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center px-4">
      <div className="w-full max-w-sm">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-red-950 border border-red-800 mb-4">
            <span className="text-2xl">🛡️</span>
          </div>
          <h1 className="text-xl font-bold text-white">관리자 포털</h1>
          <p className="text-slate-500 text-sm mt-1">Malicious Site Detector</p>
        </div>

        <div className="flex mb-6 bg-slate-900 rounded-lg p-1 border border-slate-800">
          {(['login', 'setup'] as const).map((t) => (
            <button
              key={t}
              onClick={() => { setTab(t); setError('') }}
              className={`flex-1 py-2 rounded-md text-sm font-medium transition-colors
                ${tab === t ? 'bg-slate-700 text-white' : 'text-slate-400 hover:text-white'}`}
            >
              {t === 'login' ? '로그인' : '초기 설정'}
            </button>
          ))}
        </div>

        <form
          onSubmit={tab === 'login' ? handleLogin : handleSetup}
          className="bg-slate-900 border border-slate-800 rounded-2xl p-7 space-y-4"
        >
          {tab === 'setup' && (
            <div>
              <label className="block text-slate-400 text-sm mb-1.5">관리자 이름</label>
              <input
                type="text"
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="홍길동"
                className="w-full bg-slate-800 border border-slate-700 text-white placeholder-slate-500
                           rounded-lg px-4 py-3 text-sm outline-none focus:border-red-500 transition-colors"
              />
            </div>
          )}
          <div>
            <label className="block text-slate-400 text-sm mb-1.5">이메일</label>
            <input
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="admin@example.com"
              className="w-full bg-slate-800 border border-slate-700 text-white placeholder-slate-500
                         rounded-lg px-4 py-3 text-sm outline-none focus:border-red-500 transition-colors"
            />
          </div>
          <div>
            <label className="block text-slate-400 text-sm mb-1.5">비밀번호</label>
            <input
              type="password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              className="w-full bg-slate-800 border border-slate-700 text-white placeholder-slate-500
                         rounded-lg px-4 py-3 text-sm outline-none focus:border-red-500 transition-colors"
            />
          </div>

          {error && (
            <p className="text-red-400 text-sm bg-red-950/40 border border-red-900 rounded-lg px-3 py-2">
              {error}
            </p>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-red-600 hover:bg-red-500 disabled:bg-slate-700 disabled:text-slate-500
                       text-white font-semibold py-3 rounded-lg text-sm transition-colors"
          >
            {loading ? '처리 중...' : tab === 'login' ? '로그인' : '계정 생성'}
          </button>
        </form>
      </div>
    </div>
  )
}
