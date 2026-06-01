'use client'

import { useState } from 'react'
import Link from 'next/link'
import { register, verifyEmail, resendCode, extractError } from '@/lib/api'

// 허용 특수문자 (셸 간섭 문자 제외)
const ALLOWED_SPECIAL = /[!@#%^*\-_+=?~.,]/
const ONLY_ALLOWED = /^[A-Za-z0-9!@#%^*\-_+=?~.,]+$/

interface PwCheck {
  label: string
  ok: boolean
}

function checkPassword(pw: string): PwCheck[] {
  return [
    { label: '8자 이상', ok: pw.length >= 8 },
    { label: '영문자 포함', ok: /[A-Za-z]/.test(pw) },
    { label: '숫자 포함', ok: /[0-9]/.test(pw) },
    { label: '특수문자 포함 (!@#%^*-_+=?~.,)', ok: ALLOWED_SPECIAL.test(pw) },
    { label: '허용되지 않는 문자 없음', ok: pw.length > 0 && ONLY_ALLOWED.test(pw) },
  ]
}

export default function RegisterPage() {
  // Step 1: 정보 입력 / Step 2: 코드 인증
  const [step, setStep] = useState<1 | 2>(1)
  const [pendingEmail, setPendingEmail] = useState('')
  const [pendingNickname, setPendingNickname] = useState('')

  // Step 1 fields
  const [email, setEmail] = useState('')
  const [nickname, setNickname] = useState('')
  const [password, setPassword] = useState('')
  const [pwFocused, setPwFocused] = useState(false)

  // Step 2 fields
  const [code, setCode] = useState('')
  const [resendMsg, setResendMsg] = useState('')
  const [resendCooldown, setResendCooldown] = useState(false)

  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const pwChecks = checkPassword(password)
  const pwValid = pwChecks.every((c) => c.ok)

  // ── Step 1: 회원가입 제출 ──────────────────────────────────────────
  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!pwValid) { setError('비밀번호 조건을 모두 충족해야 합니다.'); return }
    if (!nickname.trim()) { setError('닉네임을 입력해주세요.'); return }

    setError('')
    setLoading(true)
    try {
      const res = await register(email, password, nickname.trim())
      setPendingEmail(res.email)
      setPendingNickname(nickname.trim())
      setStep(2)
    } catch (err: unknown) {
      setError(extractError(err, '회원가입에 실패했습니다'))
    } finally {
      setLoading(false)
    }
  }

  // ── Step 2: 코드 인증 ─────────────────────────────────────────────
  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault()
    if (code.length !== 6) { setError('6자리 코드를 입력해주세요.'); return }

    setError('')
    setLoading(true)
    try {
      const token = await verifyEmail(pendingEmail, code)
      localStorage.setItem('token', token)
      localStorage.setItem('nickname', pendingNickname)
      window.location.href = '/dashboard'
    } catch (err: unknown) {
      setError(extractError(err, '인증에 실패했습니다'))
    } finally {
      setLoading(false)
    }
  }

  const handleResend = async () => {
    if (resendCooldown) return
    setResendMsg('')
    setError('')
    setResendCooldown(true)
    try {
      const res = await resendCode(pendingEmail)
      setResendMsg(res.message)
    } catch (err: unknown) {
      setError(extractError(err, '재발송에 실패했습니다'))
    }
    setTimeout(() => setResendCooldown(false), 30_000)
  }

  return (
    <div className="min-h-[80vh] flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        <h1 className="text-2xl font-bold text-white mb-2 text-center">회원가입</h1>
        <p className="text-slate-400 text-sm text-center mb-8">
          {step === 1
            ? '무료로 가입하고 검사 이력을 저장하세요'
            : `${pendingEmail}로 전송된 인증 코드를 입력하세요`}
        </p>

        {/* ── Step indicator ── */}
        <div className="flex items-center justify-center gap-2 mb-8">
          {[1, 2].map((s) => (
            <div key={s} className="flex items-center gap-2">
              <div
                className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold border
                  ${step === s
                    ? 'border-red-500 bg-red-600 text-white'
                    : step > s
                    ? 'border-green-600 bg-green-600 text-white'
                    : 'border-slate-700 text-slate-500'
                  }`}
              >
                {step > s ? '✓' : s}
              </div>
              {s < 2 && <div className="w-10 h-px bg-slate-700" />}
            </div>
          ))}
        </div>

        {/* ── Step 1: 정보 입력 ── */}
        {step === 1 && (
          <form onSubmit={handleRegister} className="bg-slate-800 border border-slate-700 rounded-2xl p-8 space-y-5">
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
              <label className="block text-slate-400 text-sm mb-1.5">닉네임</label>
              <input
                type="text"
                required
                value={nickname}
                onChange={(e) => setNickname(e.target.value)}
                className="w-full bg-slate-700 border border-slate-600 text-white placeholder-slate-500
                           rounded-lg px-4 py-3 outline-none focus:border-red-500 transition-colors"
                placeholder="홍길동"
              />
            </div>

            <div>
              <label className="block text-slate-400 text-sm mb-1.5">비밀번호</label>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                onFocus={() => setPwFocused(true)}
                className={`w-full bg-slate-700 border text-white placeholder-slate-500
                            rounded-lg px-4 py-3 outline-none transition-colors
                            ${password.length > 0
                              ? pwValid ? 'border-green-600 focus:border-green-500' : 'border-red-700 focus:border-red-500'
                              : 'border-slate-600 focus:border-red-500'
                            }`}
                placeholder="••••••••"
              />

              {(pwFocused || password.length > 0) && (
                <ul className="mt-2.5 space-y-1">
                  {pwChecks.map((c) => (
                    <li key={c.label} className="flex items-center gap-2 text-xs">
                      <span className={c.ok ? 'text-green-400' : 'text-slate-600'}>{c.ok ? '✓' : '○'}</span>
                      <span className={c.ok ? 'text-green-400' : 'text-slate-500'}>{c.label}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {error && <p className="text-red-400 text-sm">{error}</p>}

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-red-600 hover:bg-red-500 disabled:bg-slate-700 disabled:text-slate-500
                         text-white font-semibold py-3 rounded-lg transition-colors"
            >
              {loading ? '처리 중...' : '다음 — 이메일 인증'}
            </button>

            <p className="text-center text-sm text-slate-400">
              이미 계정이 있으신가요?{' '}
              <Link href="/auth/login" className="text-red-400 hover:underline">
                로그인
              </Link>
            </p>
          </form>
        )}

        {/* ── Step 2: 코드 인증 ── */}
        {step === 2 && (
          <form onSubmit={handleVerify} className="bg-slate-800 border border-slate-700 rounded-2xl p-8 space-y-5">
            <div>
              <label className="block text-slate-400 text-sm mb-1.5">인증 코드 (6자리)</label>
              <input
                type="text"
                inputMode="numeric"
                maxLength={6}
                required
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                className="w-full bg-slate-700 border border-slate-600 text-white placeholder-slate-500
                           rounded-lg px-4 py-3 outline-none focus:border-red-500 transition-colors
                           text-center text-2xl tracking-[0.5em] font-mono"
                placeholder="------"
                autoFocus
              />
            </div>

            {error && <p className="text-red-400 text-sm">{error}</p>}
            {resendMsg && <p className="text-green-400 text-sm">{resendMsg}</p>}

            <button
              type="submit"
              disabled={loading || code.length !== 6}
              className="w-full bg-red-600 hover:bg-red-500 disabled:bg-slate-700 disabled:text-slate-500
                         text-white font-semibold py-3 rounded-lg transition-colors"
            >
              {loading ? '인증 중...' : '인증 완료'}
            </button>

            <p className="text-center text-sm text-slate-500">
              코드를 받지 못하셨나요?{' '}
              <button
                type="button"
                onClick={handleResend}
                disabled={resendCooldown}
                className="text-red-400 hover:underline disabled:text-slate-600 disabled:no-underline"
              >
                {resendCooldown ? '30초 후 재발송 가능' : '재발송'}
              </button>
            </p>

            <button
              type="button"
              onClick={() => { setStep(1); setCode(''); setError(''); setResendMsg('') }}
              className="w-full text-slate-500 hover:text-slate-300 text-sm transition-colors"
            >
              ← 이전으로
            </button>
          </form>
        )}
      </div>
    </div>
  )
}
