'use client'

import Link from 'next/link'
import { useEffect, useState } from 'react'
import { usePathname } from 'next/navigation'

function ShieldIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" className="w-5 h-5 text-red-400 shrink-0">
      <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-1 14l-3-3 1.41-1.41L11 12.17l4.59-4.58L17 9l-6 6z" />
    </svg>
  )
}

export default function Navbar() {
  const [isLoggedIn, setIsLoggedIn] = useState(false)
  const pathname = usePathname()

  useEffect(() => {
    setIsLoggedIn(!!localStorage.getItem('token'))
  }, [pathname])

  const logout = () => {
    localStorage.removeItem('token')
    localStorage.removeItem('nickname')
    setIsLoggedIn(false)
    window.location.href = '/'
  }

  const linkClass = (href: string) =>
    `text-sm transition-colors ${
      pathname === href
        ? 'text-white font-medium'
        : 'text-slate-400 hover:text-white'
    }`

  return (
    <nav className="sticky top-0 z-50 bg-slate-900/80 backdrop-blur-md border-b border-slate-800">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 h-14 flex items-center justify-between gap-4">
        <Link href="/" className="flex items-center gap-2 font-bold text-base text-white shrink-0">
          <ShieldIcon />
          <span>
            Malicious<span className="text-red-400">Scan</span>
          </span>
        </Link>

        <div className="flex items-center gap-5">
          <Link href="/community" className={linkClass('/community')}>
            커뮤니티
          </Link>
          {isLoggedIn ? (
            <>
              <Link href="/dashboard" className={linkClass('/dashboard')}>
                대시보드
              </Link>
              <button
                onClick={logout}
                className="text-sm text-slate-400 hover:text-white transition-colors"
              >
                로그아웃
              </button>
            </>
          ) : (
            <>
              <Link href="/auth/login" className={linkClass('/auth/login')}>
                로그인
              </Link>
              <Link
                href="/auth/register"
                className="bg-red-600 hover:bg-red-500 text-white text-sm font-medium px-4 py-1.5 rounded-lg transition-colors"
              >
                회원가입
              </Link>
            </>
          )}
        </div>
      </div>
    </nav>
  )
}
