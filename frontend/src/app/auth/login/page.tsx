'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import { login, extractError } from '@/lib/api'

export default function LoginPage() {
  const router = useRouter()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const token = await login(email, password)
      localStorage.setItem('token', token)
      // JWT payload에서 닉네임 추출
      try {
        const payload = JSON.parse(atob(token.split('.')[1]))
        if (payload.nickname) localStorage.setItem('nickname', payload.nickname)
      } catch {}
      window.location.href = '/dashboard'
    } catch (err: unknown) {
      setError(extractError(err, '로그인에 실패했습니다'))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-[80vh] flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        <h1 className="text-2xl font-bold text-white mb-2 text-center">로그인</h1>
        <p className="text-slate-400 text-sm text-center mb-8">
          검사 이력 저장 및 대시보드 이용을 위해 로그인하세요
        </p>

        <form onSubmit={handleSubmit} className="bg-slate-800 border border-slate-700 rounded-2xl p-8 space-y-5">
          <div>
            <label className="block text-slate-400 text-sm mb-1.5">이메일</label>
            <input
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full bg-slate-700 border border-slate-600 text-white placeholder-slate-500
                         rounded-lg px-4 py-3 outline-none focus:border-red-500 transition-colors"
              placeholder="you@example.com"
            />
          </div>
          <div>
            <label className="block text-slate-400 text-sm mb-1.5">비밀번호</label>
            <input
              type="password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full bg-slate-700 border border-slate-600 text-white placeholder-slate-500
                         rounded-lg px-4 py-3 outline-none focus:border-red-500 transition-colors"
              placeholder="••••••••"
            />
          </div>

          {error && <p className="text-red-400 text-sm">{error}</p>}

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-red-600 hover:bg-red-500 disabled:bg-slate-700 disabled:text-slate-500
                       text-white font-semibold py-3 rounded-lg transition-colors"
          >
            {loading ? '로그인 중...' : '로그인'}
          </button>

          <p className="text-center text-sm text-slate-400">
            계정이 없으신가요?{' '}
            <Link href="/auth/register" className="text-red-400 hover:underline">
              회원가입
            </Link>
          </p>
        </form>
      </div>
    </div>
  )
}
