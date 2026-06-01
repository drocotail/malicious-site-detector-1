'use client'

import { useRouter } from 'next/navigation'
import { useEffect, useState } from 'react'
import { getRecentThreats, getStats, Threat, Stats } from '@/lib/api'

const CATEGORY_LABELS: Record<string, string> = {
  confirmed_phishing: '확정 피싱',
  suspicious: '의심 사이트',
  malware: '악성코드',
  user_reported: '사용자 제보',
}

const CATEGORY_COLORS: Record<string, string> = {
  confirmed_phishing: 'bg-red-900 text-red-200',
  suspicious: 'bg-yellow-900 text-yellow-200',
  malware: 'bg-red-900 text-red-200',
  user_reported: 'bg-blue-900 text-blue-200',
}

function timeAgo(iso: string): string {
  const diff = Math.floor((Date.now() - new Date(iso).getTime()) / 1000)
  if (diff < 60) return `${diff}초 전`
  if (diff < 3600) return `${Math.floor(diff / 60)}분 전`
  if (diff < 86400) return `${Math.floor(diff / 3600)}시간 전`
  return `${Math.floor(diff / 86400)}일 전`
}

export default function HomePage() {
  const router = useRouter()
  const [url, setUrl] = useState('')
  const [threats, setThreats] = useState<Threat[]>([])
  const [stats, setStats] = useState<Stats | null>(null)
  useEffect(() => {
    Promise.all([getRecentThreats(), getStats()])
      .then(([t, s]) => { setThreats(t); setStats(s) })
      .catch(() => {})
  }, [])

  const handleScan = (e: React.FormEvent) => {
    e.preventDefault()
    if (!url.trim()) return
    router.push(`/results?url=${encodeURIComponent(url.trim())}`)
  }

  return (
    <div className="max-w-6xl mx-auto px-4 py-16 bg-grid">
      {/* Hero */}
      <section className="relative text-center mb-16 animate-slide-up">
        <div className="absolute inset-0 overflow-hidden pointer-events-none -z-10">
          <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[600px] h-64 bg-red-600/10 rounded-full blur-3xl" />
        </div>

        <div className="inline-flex items-center gap-2 bg-red-950/80 text-red-300 text-sm px-4 py-1.5 rounded-full mb-6 border border-red-800/60 backdrop-blur-sm">
          <span className="w-2 h-2 rounded-full bg-red-400 animate-pulse inline-block" />
          실시간 위협 탐지 활성화
        </div>

        <h1 className="text-5xl sm:text-6xl font-bold text-white mb-4 tracking-tight">
          사이트{' '}
          <span className="bg-gradient-to-r from-red-400 via-red-500 to-rose-500 bg-clip-text text-transparent">
            안전 검사기
          </span>
        </h1>
        <p className="text-slate-400 text-lg mb-10 max-w-xl mx-auto leading-relaxed">
          URL을 입력하면 Google Safe Browsing · PhishTank · 자체 AI 분석으로<br />
          피싱 및 악성 사이트 여부를 즉시 판별합니다
        </p>

        <form onSubmit={handleScan} className="flex gap-3 max-w-2xl mx-auto">
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com 또는 도메인만 입력"
            className="flex-1 bg-slate-800/80 border border-slate-600 text-white placeholder-slate-500
                       rounded-xl px-5 py-4 text-base outline-none focus:border-red-500 focus:ring-1 focus:ring-red-500/30 transition-all"
          />
          <button
            type="submit"
            style={{
              backgroundColor: url.trim() ? '#dc2626' : '#334155',
              color: url.trim() ? '#fff' : '#64748b',
              cursor: url.trim() ? 'pointer' : 'not-allowed',
            }}
            className="font-semibold px-8 py-4 rounded-xl transition-all whitespace-nowrap"
          >
            검사하기
          </button>
        </form>

        <p className="text-slate-600 text-sm mt-3">
          예시: https://naver.com · paypal-security-update.xyz · google.com
        </p>
      </section>

      {/* Stats */}
      {stats && (
        <section className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-16 animate-fade-in">
          {[
            { label: '총 검사 수', value: stats.total_scans.toLocaleString(), icon: '🔍' },
            { label: '위험 탐지', value: stats.dangerous_detected.toLocaleString(), icon: '🚨', color: 'text-red-400' },
            { label: '주의 탐지', value: stats.suspicious_detected.toLocaleString(), icon: '⚠️', color: 'text-yellow-400' },
            { label: 'DB 등록 사이트', value: stats.db_entries.toLocaleString(), icon: '🗄️' },
          ].map((s) => (
            <div key={s.label} className="bg-slate-800/60 border border-slate-700/80 rounded-xl p-5 text-center hover:border-slate-600 transition-colors">
              <div className="text-2xl mb-1">{s.icon}</div>
              <div className={`text-2xl font-bold ${s.color ?? 'text-white'}`}>{s.value}</div>
              <div className="text-slate-400 text-sm mt-1">{s.label}</div>
            </div>
          ))}
        </section>
      )}

      {/* Recent Threats */}
      <section>
        <h2 className="text-xl font-semibold text-white mb-4 flex items-center gap-2">
          <span className="text-red-400">&#9888;</span> DB 등록 위협 사이트
        </h2>

        {threats.length === 0 ? (
          <div className="bg-slate-800/60 border border-slate-700 rounded-xl p-8 text-center text-slate-500">
            등록된 위협 사이트가 없습니다
          </div>
        ) : (
          <div className="bg-slate-800/60 border border-slate-700 rounded-xl overflow-hidden">
            <table className="w-full text-sm">
              <thead className="border-b border-slate-700 bg-slate-800/80">
                <tr>
                  {['도메인', '분류', '비고', '등록 시간'].map((h) => (
                    <th key={h} className="text-left text-slate-400 font-medium px-5 py-3">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {threats.map((t) => (
                  <tr
                    key={t.id}
                    className="border-b border-slate-700/50 last:border-0 hover:bg-slate-700/30 transition-colors"
                  >
                    <td className="px-5 py-3 font-mono text-slate-300">{t.domain}</td>
                    <td className="px-5 py-3">
                      <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${CATEGORY_COLORS[t.category ?? ''] ?? 'bg-slate-700 text-slate-300'}`}>
                        {CATEGORY_LABELS[t.category ?? ''] ?? t.category ?? '미분류'}
                      </span>
                    </td>
                    <td className="px-5 py-3 text-slate-400 max-w-xs truncate">{t.notes ?? '-'}</td>
                    <td className="px-5 py-3 text-slate-500">{timeAgo(t.registered_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* How it works */}
      <section className="mt-20 grid md:grid-cols-3 gap-6">
        {[
          {
            step: '01',
            title: 'API 이중 검사',
            desc: 'Google Safe Browsing과 PhishTank를 동시에 조회해 알려진 위협을 탐지합니다.',
            icon: '🔒',
          },
          {
            step: '02',
            title: 'AI + 규칙 분석',
            desc: 'URLBert AI 모델과 규칙 기반 엔진이 도메인 나이, 사칭 패턴, 의심 TLD를 분석합니다.',
            icon: '🧠',
          },
          {
            step: '03',
            title: '자체 DB 누적',
            desc: '탐지된 위협 사이트는 자체 데이터베이스에 저장되어 다음 조회 시 즉시 반환됩니다.',
            icon: '🗄️',
          },
        ].map((item) => (
          <div key={item.step} className="bg-slate-800/60 border border-slate-700/80 rounded-xl p-6 hover:border-slate-600 hover:bg-slate-800 transition-all">
            <div className="text-3xl mb-3">{item.icon}</div>
            <div className="text-red-400 text-xs font-bold mb-1 tracking-widest">STEP {item.step}</div>
            <h3 className="font-semibold text-white mb-2">{item.title}</h3>
            <p className="text-slate-400 text-sm leading-relaxed">{item.desc}</p>
          </div>
        ))}
      </section>
    </div>
  )
}
