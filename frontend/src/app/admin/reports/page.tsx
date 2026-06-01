'use client'

import { useEffect, useState } from 'react'
import { getAdminReports, reviewReport, AdminReport, extractAdminError } from '@/lib/adminApi'

const STATUS_TABS = [
  { key: 'pending', label: '검토 대기', color: 'text-yellow-400' },
  { key: 'approved', label: '승인됨', color: 'text-green-400' },
  { key: 'rejected', label: '거절됨', color: 'text-slate-400' },
  { key: 'all', label: '전체', color: 'text-white' },
] as const

function timeAgo(iso: string) {
  const diff = Math.floor((Date.now() - new Date(iso).getTime()) / 1000)
  if (diff < 3600) return `${Math.floor(diff / 60)}분 전`
  if (diff < 86400) return `${Math.floor(diff / 3600)}시간 전`
  return `${Math.floor(diff / 86400)}일 전`
}

export default function AdminReportsPage() {
  const [reports, setReports] = useState<AdminReport[]>([])
  const [loading, setLoading] = useState(true)
  const [tab, setTab] = useState<'pending' | 'approved' | 'rejected' | 'all'>('pending')
  const [processingId, setProcessingId] = useState<number | null>(null)
  const [toast, setToast] = useState('')

  const load = (t = tab) => {
    setLoading(true)
    getAdminReports(t)
      .then(setReports)
      .catch(() => {})
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [tab])

  const showToast = (msg: string) => {
    setToast(msg)
    setTimeout(() => setToast(''), 3000)
  }

  const handleReview = async (id: number, action: 'approve' | 'reject') => {
    setProcessingId(id)
    try {
      const res = await reviewReport(id, action)
      showToast(res.message)
      setReports((prev) => prev.filter((r) => r.id !== id))
    } catch (err) {
      showToast(extractAdminError(err, '처리 중 오류가 발생했습니다.'))
    } finally {
      setProcessingId(null)
    }
  }

  return (
    <div className="p-8">
      {/* Toast */}
      {toast && (
        <div className="fixed top-6 right-6 bg-slate-800 border border-slate-600 text-white text-sm px-5 py-3 rounded-xl shadow-xl z-50">
          {toast}
        </div>
      )}

      <h1 className="text-2xl font-bold text-white mb-2">의심 사이트 제보 검토</h1>
      <p className="text-slate-500 text-sm mb-6">사용자가 제보한 의심 사이트를 검토하고 승인하거나 거절하세요</p>

      {/* 탭 */}
      <div className="flex gap-1 mb-6 bg-slate-900 border border-slate-800 rounded-xl p-1 w-fit">
        {STATUS_TABS.map(({ key, label, color }) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            className={`px-5 py-2 rounded-lg text-sm font-medium transition-colors
              ${tab === key ? 'bg-slate-700 text-white' : `${color} hover:text-white`}`}
          >
            {label}
          </button>
        ))}
      </div>

      {loading ? (
        <div className="text-center py-20 text-slate-500">불러오는 중...</div>
      ) : reports.length === 0 ? (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-16 text-center">
          <div className="text-4xl mb-4">
            {tab === 'pending' ? '✅' : '📭'}
          </div>
          <p className="text-slate-500">
            {tab === 'pending' ? '검토 대기 중인 제보가 없습니다' : '해당 항목이 없습니다'}
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {reports.map((r) => (
            <div
              key={r.id}
              className="bg-slate-900 border border-slate-800 rounded-xl p-5 hover:border-slate-700 transition-colors"
            >
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1 min-w-0">
                  {/* URL + 도메인 */}
                  <div className="flex items-center gap-2 mb-2">
                    <span className="text-red-400 font-mono text-sm font-medium truncate">
                      {r.domain}
                    </span>
                    {r.status !== 'pending' && (
                      <span className={`text-xs px-2 py-0.5 rounded-full border font-medium
                        ${r.status === 'approved'
                          ? 'bg-green-950 text-green-300 border-green-800'
                          : 'bg-slate-800 text-slate-400 border-slate-700'
                        }`}>
                        {r.status === 'approved' ? '승인됨' : '거절됨'}
                      </span>
                    )}
                  </div>

                  <p className="text-slate-500 text-xs font-mono mb-3 truncate">{r.url}</p>

                  {/* 설명 */}
                  {r.description && (
                    <p className="text-slate-300 text-sm bg-slate-800/60 rounded-lg px-3 py-2 mb-3">
                      {r.description}
                    </p>
                  )}

                  {/* 메타 정보 */}
                  <div className="flex items-center gap-4 text-xs text-slate-600">
                    <span>제보자: {r.reporter_nickname ?? '비로그인'}</span>
                    <span>제출: {timeAgo(r.created_at)}</span>
                    {r.reviewed_at && <span>처리: {timeAgo(r.reviewed_at)}</span>}
                  </div>
                </div>

                {/* 액션 버튼 (대기 중일 때만) */}
                {r.status === 'pending' && (
                  <div className="flex gap-2 shrink-0">
                    <button
                      onClick={() => handleReview(r.id, 'approve')}
                      disabled={processingId === r.id}
                      className="bg-red-600 hover:bg-red-500 disabled:bg-slate-700 disabled:text-slate-500
                                 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors"
                    >
                      {processingId === r.id ? '...' : '승인'}
                    </button>
                    <button
                      onClick={() => handleReview(r.id, 'reject')}
                      disabled={processingId === r.id}
                      className="border border-slate-700 hover:border-slate-600 text-slate-400 hover:text-white
                                 text-sm font-medium px-4 py-2 rounded-lg transition-colors"
                    >
                      거절
                    </button>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
