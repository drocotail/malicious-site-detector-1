'use client'

import { useEffect, useState } from 'react'
import { getAdminScans, AdminScan } from '@/lib/adminApi'

const VERDICT_BADGE: Record<string, string> = {
  dangerous: 'bg-red-950 text-red-300 border border-red-800',
  suspicious: 'bg-yellow-950 text-yellow-300 border border-yellow-800',
  safe: 'bg-green-950 text-green-300 border border-green-800',
}
const VERDICT_LABEL: Record<string, string> = {
  dangerous: '위험',
  suspicious: '주의',
  safe: '안전',
}

function timeAgo(iso: string) {
  const diff = Math.floor((Date.now() - new Date(iso).getTime()) / 1000)
  if (diff < 3600) return `${Math.floor(diff / 60)}분 전`
  if (diff < 86400) return `${Math.floor(diff / 3600)}시간 전`
  return `${Math.floor(diff / 86400)}일 전`
}

export default function AdminScansPage() {
  const [scans, setScans] = useState<AdminScan[]>([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState<'all' | 'dangerous' | 'suspicious' | 'safe'>('all')

  useEffect(() => {
    getAdminScans(0, 100)
      .then(setScans)
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  const filtered = filter === 'all' ? scans : scans.filter((s) => s.verdict === filter)

  return (
    <div className="p-8">
      <h1 className="text-2xl font-bold text-white mb-2">스캔 이력</h1>
      <p className="text-slate-500 text-sm mb-6">최근 100건</p>

      <div className="flex gap-2 mb-5">
        {(['all', 'dangerous', 'suspicious', 'safe'] as const).map((v) => (
          <button
            key={v}
            onClick={() => setFilter(v)}
            className={`px-4 py-1.5 rounded-lg text-sm font-medium transition-colors border
              ${filter === v
                ? 'bg-slate-700 text-white border-slate-600'
                : 'text-slate-400 border-slate-800 hover:border-slate-700 hover:text-white'
              }`}
          >
            {v === 'all' ? '전체' : VERDICT_LABEL[v]}
            <span className="ml-1.5 text-xs opacity-60">
              {v === 'all' ? scans.length : scans.filter((s) => s.verdict === v).length}
            </span>
          </button>
        ))}
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        {loading ? (
          <div className="text-center py-16 text-slate-500">불러오는 중...</div>
        ) : filtered.length === 0 ? (
          <div className="text-center py-16 text-slate-500">검색 결과가 없습니다</div>
        ) : (
          <table className="w-full text-sm">
            <thead className="border-b border-slate-800 bg-slate-900/80">
              <tr>
                {['URL', '판정', '위험 점수', '위협 유형', '사용자', '시간'].map((h) => (
                  <th key={h} className="text-left text-slate-500 font-medium px-4 py-3">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map((s) => (
                <tr key={s.id} className="border-b border-slate-800/60 last:border-0 hover:bg-slate-800/30">
                  <td className="px-4 py-3 font-mono text-slate-300 max-w-[220px] truncate">{s.url}</td>
                  <td className="px-4 py-3">
                    <span className={`text-xs px-2 py-0.5 rounded-md font-medium ${VERDICT_BADGE[s.verdict] ?? ''}`}>
                      {VERDICT_LABEL[s.verdict] ?? s.verdict}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`font-bold ${s.risk_score >= 70 ? 'text-red-400' : s.risk_score >= 40 ? 'text-yellow-400' : 'text-green-400'}`}>
                      {s.risk_score}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-slate-500 text-xs max-w-[160px] truncate">
                    {s.threat_types?.join(', ') || '-'}
                  </td>
                  <td className="px-4 py-3 text-slate-600 text-xs">
                    {s.user_id ? `#${s.user_id}` : '비로그인'}
                  </td>
                  <td className="px-4 py-3 text-slate-600 text-xs whitespace-nowrap">{timeAgo(s.scanned_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
