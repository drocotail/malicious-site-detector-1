'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { getAdminStats, AdminStats } from '@/lib/adminApi'

export default function AdminDashboardPage() {
  const [stats, setStats] = useState<AdminStats | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    getAdminStats()
      .then(setStats)
      .catch(() => setError('통계를 불러오지 못했습니다.'))
  }, [])

  return (
    <div className="p-8">
      <h1 className="text-2xl font-bold text-white mb-2">대시보드</h1>
      <p className="text-slate-500 text-sm mb-8">서비스 전체 현황</p>

      {error && <p className="text-red-400 text-sm mb-6">{error}</p>}

      {stats ? (
        <>
          {/* 핵심 지표 */}
          {stats.pending_reports > 0 && (
            <Link href="/admin/reports">
              <div className="bg-yellow-950/60 border border-yellow-700 rounded-xl p-4 mb-6 flex items-center gap-4 hover:bg-yellow-950/80 transition-colors cursor-pointer">
                <span className="text-2xl">🔔</span>
                <div>
                  <p className="text-yellow-300 font-semibold">
                    검토 대기 중인 제보 {stats.pending_reports}건
                  </p>
                  <p className="text-yellow-600 text-sm">클릭하여 제보 검토 페이지로 이동</p>
                </div>
              </div>
            </Link>
          )}

          {stats.blocked_users > 0 && (
            <div className="bg-red-950/40 border border-red-900 rounded-xl p-4 mb-6 flex items-center gap-4">
              <span className="text-2xl">🚫</span>
              <p className="text-red-300 text-sm">
                현재 <span className="font-bold">{stats.blocked_users}명</span>의 사용자가 차단 중입니다
              </p>
            </div>
          )}

          {/* 통계 그리드 */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            {[
              { label: '총 스캔', value: stats.total_scans, icon: '🔍', color: 'text-white' },
              { label: '위험 탐지', value: stats.dangerous, icon: '🚨', color: 'text-red-400' },
              { label: '주의 탐지', value: stats.suspicious, icon: '⚠️', color: 'text-yellow-400' },
              { label: '안전', value: stats.safe, icon: '✅', color: 'text-green-400' },
              { label: '등록 악성 사이트', value: stats.total_sites, icon: '🗄️', color: 'text-white' },
              { label: '확정 피싱', value: stats.confirmed_phishing, icon: '🎣', color: 'text-red-400' },
              { label: '가입 사용자', value: stats.total_users, icon: '👥', color: 'text-white' },
              { label: '커뮤니티 게시글', value: stats.total_posts, icon: '📋', color: 'text-white' },
            ].map((c) => (
              <div
                key={c.label}
                className="bg-slate-900 border border-slate-800 rounded-xl p-5 hover:border-slate-700 transition-colors"
              >
                <div className="text-2xl mb-2">{c.icon}</div>
                <div className={`text-3xl font-bold ${c.color}`}>{c.value.toLocaleString()}</div>
                <div className="text-slate-500 text-sm mt-1">{c.label}</div>
              </div>
            ))}
          </div>
        </>
      ) : (
        !error && (
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            {Array.from({ length: 8 }).map((_, i) => (
              <div key={i} className="bg-slate-900 border border-slate-800 rounded-xl p-5 animate-pulse">
                <div className="h-6 w-8 bg-slate-800 rounded mb-2" />
                <div className="h-8 w-16 bg-slate-800 rounded mb-2" />
                <div className="h-4 w-24 bg-slate-800 rounded" />
              </div>
            ))}
          </div>
        )
      )}
    </div>
  )
}
