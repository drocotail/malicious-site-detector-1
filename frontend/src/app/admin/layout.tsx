'use client'

import { useEffect, useState } from 'react'
import { useRouter, usePathname } from 'next/navigation'
import Link from 'next/link'

const NAV = [
  { href: '/admin', label: '대시보드', icon: '📊' },
  { href: '/admin/reports', label: '제보 검토', icon: '🔔' },
  { href: '/admin/users', label: '사용자 관리', icon: '👥' },
  { href: '/admin/sites', label: '악성 사이트', icon: '🚨' },
  { href: '/admin/scans', label: '스캔 이력', icon: '🔍' },
  { href: '/admin/posts', label: '게시글', icon: '📋' },
]

export default function AdminLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter()
  const pathname = usePathname()
  const [adminName, setAdminName] = useState('')

  useEffect(() => {
    if (pathname === '/admin/login') return
    const token = localStorage.getItem('admin_token')
    if (!token) { router.replace('/admin/login'); return }
    try {
      const payload = JSON.parse(atob(token.split('.')[1]))
      setAdminName(payload.name ?? '관리자')
    } catch {}
  }, [pathname, router])

  if (pathname === '/admin/login') return <>{children}</>

  const handleLogout = () => {
    localStorage.removeItem('admin_token')
    router.replace('/admin/login')
  }

  return (
    <div className="flex min-h-screen bg-slate-950">
      {/* 사이드바 */}
      <aside className="w-56 bg-slate-900 border-r border-slate-800 flex flex-col shrink-0">
        <div className="px-5 py-5 border-b border-slate-800">
          <div className="text-red-400 font-bold text-sm tracking-widest uppercase">Admin</div>
          <div className="text-slate-400 text-xs mt-1 truncate">{adminName}</div>
        </div>

        <nav className="flex-1 py-4 space-y-0.5">
          {NAV.map(({ href, label, icon }) => {
            const active = pathname === href
            return (
              <Link
                key={href}
                href={href}
                className={`flex items-center gap-3 px-5 py-2.5 text-sm transition-colors
                  ${active
                    ? 'bg-red-950/60 text-red-300 border-r-2 border-red-500'
                    : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
                  }`}
              >
                <span>{icon}</span>
                {label}
              </Link>
            )
          })}
        </nav>

        <div className="px-5 py-4 border-t border-slate-800">
          <button
            onClick={handleLogout}
            className="w-full text-left text-slate-500 hover:text-red-400 text-sm transition-colors"
          >
            로그아웃
          </button>
        </div>
      </aside>

      {/* 메인 */}
      <main className="flex-1 overflow-auto">{children}</main>
    </div>
  )
}
