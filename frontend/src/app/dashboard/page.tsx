'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import { getScanHistory, reportUrl, extractError, ScanRecord } from '@/lib/api'

// Backend stores verdict as Korean: '위험' | '주의' | '낮음'
const VERDICT_BADGE: Record<string, string> = {
  '위험': 'bg-red-900 text-red-300',
  '주의': 'bg-yellow-900 text-yellow-300',
  '낮음': 'bg-green-900 text-green-300',
}

function timeAgo(iso: string): string {
  const diff = Math.floor((Date.now() - new Date(iso).getTime()) / 1000)
  if (diff < 60) return `${diff}초 전`
  if (diff < 3600) return `${Math.floor(diff / 60)}분 전`
  if (diff < 86400) return `${Math.floor(diff / 3600)}시간 전`
  return `${Math.floor(diff / 86400)}일 전`
}

export default function DashboardPage() {
  const router = useRouter()
  const [history, setHistory] = useState<ScanRecord[]>([])
  const [loading, setLoading] = useState(true)
  const [nickname, setNickname] = useState('')
  const [reportUrl_, setReportUrl] = useState('')
  const [reportMsg, setReportMsg] = useState('')

  useEffect(() => {
    const token = localStorage.getItem('token')
    if (!token) { router.push('/auth/login'); return }
    setNickname(localStorage.getItem('nickname') ?? '')

    getScanHistory()
      .then(setHistory)
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [router])

  const handleReport = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!reportUrl_.trim()) return
    try {
      const res = await reportUrl(reportUrl_.trim(), '사용자 제보')
      setReportMsg(res.message ?? '제보가 접수되었습니다')
      setReportUrl('')
    } catch (err: unknown) {
      setReportMsg(extractError(err, '제보 중 오류가 발생했습니다'))
    }
  }

  const dangerous = history.filter((h) => h.verdict === '위험').length
  const suspicious = history.filter((h) => h.verdict === '주의').length

  return (
    <div className="max-w-6xl mx-auto px-4 py-10">
      {nickname && (
        <div className="bg-slate-800/60 border border-slate-700 rounded-xl px-6 py-4 mb-6 flex items-center gap-3">
          <span className="text-2xl">👋</span>
          <div>
            <p className="text-white font-semibold">{nickname}님 환영합니다!</p>
            <p className="text-slate-400 text-sm">오늘도 안전한 인터넷 이용 하세요</p>
          </div>
        </div>
      )}
      <h1 className="text-2xl font-bold text-white mb-8">대시보드</h1>

      {/* 요약 카드 */}
      <div className="grid md:grid-cols-3 gap-6 mb-10">
        <div className="bg-slate-800 border border-slate-700 rounded-xl p-5">
          <div className="text-slate-400 text-sm mb-1">총 검사</div>
          <div className="text-3xl font-bold text-white">{history.length}</div>
        </div>
        <div className="bg-slate-800 border border-slate-700 rounded-xl p-5">
          <div className="text-slate-400 text-sm mb-1">위험 탐지</div>
          <div className="text-3xl font-bold text-red-400">{dangerous}</div>
        </div>
        <div className="bg-slate-800 border border-slate-700 rounded-xl p-5">
          <div className="text-slate-400 text-sm mb-1">주의 탐지</div>
          <div className="text-3xl font-bold text-yellow-400">{suspicious}</div>
        </div>
      </div>

      {/* 의심 사이트 제보 */}
      <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 mb-8">
        <h2 className="font-semibold text-white mb-4">의심 사이트 제보</h2>
        <form onSubmit={handleReport} className="flex gap-3">
          <input
            type="text"
            value={reportUrl_}
            onChange={(e) => setReportUrl(e.target.value)}
            placeholder="https://phishing-site.xyz"
            className="flex-1 bg-slate-700 border border-slate-600 text-white placeholder-slate-500
                       rounded-lg px-4 py-2.5 text-sm outline-none focus:border-yellow-500 transition-colors"
          />
          <button
            type="submit"
            className="bg-yellow-600 hover:bg-yellow-500 text-white px-6 py-2.5 rounded-lg text-sm font-medium transition-colors"
          >
            제보
          </button>
        </form>
        {reportMsg && <p className="text-sm text-green-400 mt-2">{reportMsg}</p>}
      </div>

      {/* 검사 이력 */}
      <h2 className="font-semibold text-white mb-4">검사 이력</h2>
      {loading ? (
        <div className="text-center py-10 text-slate-400">불러오는 중...</div>
      ) : history.length === 0 ? (
        <div className="bg-slate-800 border border-slate-700 rounded-xl p-10 text-center text-slate-500">
          아직 검사 이력이 없습니다.{' '}
          <Link href="/" className="text-red-400 hover:underline">
            지금 검사하러 가기
          </Link>
        </div>
      ) : (
        <div className="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead className="border-b border-slate-700 bg-slate-800/80">
              <tr>
                {['URL', '판정', '위험 점수', '탐지 근거', '검사 시간'].map((h) => (
                  <th key={h} className="text-left text-slate-400 font-medium px-4 py-3">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {history.map((r) => (
                <tr
                  key={r.id}
                  className="border-b border-slate-700/50 last:border-0 hover:bg-slate-700/30 transition-colors cursor-pointer"
                  onClick={() => window.open(`/results?url=${encodeURIComponent(r.url)}`, '_blank')}
                >
                  <td className="px-4 py-3 font-mono text-slate-300 max-w-[200px] truncate">{r.url}</td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${VERDICT_BADGE[r.verdict] ?? 'bg-slate-700 text-slate-300'}`}>
                      {r.verdict}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`font-bold ${r.risk_score >= 70 ? 'text-red-400' : r.risk_score >= 40 ? 'text-yellow-400' : 'text-green-400'}`}>
                      {r.risk_score}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-slate-400 max-w-[220px] truncate text-xs">{r.reason || '-'}</td>
                  <td className="px-4 py-3 text-slate-500 whitespace-nowrap">{timeAgo(r.scanned_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
