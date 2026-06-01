'use client'

import { useRouter, useSearchParams } from 'next/navigation'
import { Suspense, useEffect, useState } from 'react'
import { scanUrl, reportUrl, toVerdict, ScanResult } from '@/lib/api'
import Link from 'next/link'

const VERDICT_CONFIG = {
  dangerous: {
    label: '위험',
    emoji: '🚨',
    bg: 'bg-red-950',
    border: 'border-red-700',
    badge: 'bg-red-600 text-white',
    bar: 'bg-red-500',
    text: 'text-red-400',
  },
  suspicious: {
    label: '주의',
    emoji: '⚠️',
    bg: 'bg-yellow-950',
    border: 'border-yellow-700',
    badge: 'bg-yellow-500 text-black',
    bar: 'bg-yellow-400',
    text: 'text-yellow-400',
  },
  safe: {
    label: '안전',
    emoji: '✅',
    bg: 'bg-green-950',
    border: 'border-green-700',
    badge: 'bg-green-600 text-white',
    bar: 'bg-green-500',
    text: 'text-green-400',
  },
}

const DECISION_LABELS: Record<string, string> = {
  internal_db: '자체 DB 등록 위협',
  rule_based: '규칙 기반 탐지',
  ai_model: 'AI 모델 탐지',
  api_check: 'API 검사 탐지',
  safe: '위협 없음',
}

function ResultContent() {
  const searchParams = useSearchParams()
  const router = useRouter()
  const url = searchParams.get('url') ?? ''

  const [result, setResult] = useState<ScanResult | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [reported, setReported] = useState(false)
  const [newUrl, setNewUrl] = useState('')

  useEffect(() => {
    if (!url) { router.push('/'); return }

    const timeout = setTimeout(() => {
      setLoading(false)
      setError('응답 시간이 초과되었습니다. 백엔드 서버가 실행 중인지 확인해주세요.')
    }, 30000)

    scanUrl(url)
      .then(setResult)
      .catch((e) => {
        if (e?.response?.status === 429) {
          setError('검사 요청이 너무 많습니다. 잠시 후 다시 시도해주세요.')
          return
        }
        const msg = e?.response?.data?.detail ?? e?.message ?? '검사 중 오류가 발생했습니다'
        setError(typeof msg === 'string' ? msg : '검사 중 오류가 발생했습니다')
      })
      .finally(() => { clearTimeout(timeout); setLoading(false) })

    return () => clearTimeout(timeout)
  }, [url]) // router 제거 — 재렌더링 루프 방지

  const handleReport = async () => {
    await reportUrl(url, '사용자 제보')
    setReported(true)
  }

  const handleRescan = (e: React.FormEvent) => {
    e.preventDefault()
    if (newUrl.trim()) router.push(`/results?url=${encodeURIComponent(newUrl.trim())}`)
  }

  if (loading) {
    return (
      <div className="max-w-3xl mx-auto px-4 py-20 text-center">
        <div className="text-5xl mb-6 animate-spin inline-block">⏳</div>
        <p className="text-slate-400 text-lg">AI · 규칙 기반 · 외부 API 분석 중...</p>
        <p className="text-slate-600 text-sm mt-2">{url}</p>
        <p className="text-slate-600 text-xs mt-4">첫 실행 시 AI 모델 로딩으로 30초 이상 걸릴 수 있습니다</p>
      </div>
    )
  }

  if (error) {
    return (
      <div className="max-w-3xl mx-auto px-4 py-20 text-center">
        <div className="text-5xl mb-4">❌</div>
        <p className="text-red-400 text-lg mb-2">검사 실패</p>
        <p className="text-slate-400 text-sm mb-6">{error}</p>
        <Link href="/" className="text-slate-400 hover:text-white underline text-sm">
          처음으로 돌아가기
        </Link>
      </div>
    )
  }

  if (!result) return null

  const verdict = toVerdict(result.risk_level)
  const cfg = VERDICT_CONFIG[verdict]

  const apiResults = result.api_results as {
    safe_browsing?: { skipped?: boolean; is_safe?: boolean }
    phishtank?: {
      skipped?: boolean
      available?: boolean
      in_database?: boolean
      verified?: boolean
      valid?: boolean
      is_phishing?: boolean
    }
  }

  const aiResults = result.ai_results as {
    url_transformer?: { skipped?: boolean; label?: string; score?: number }
    zero_shot?: { skipped?: boolean; label?: string; score?: number }
  }

  const ruleInfo = result.rule_info as {
    triggered_rules?: string[]
    score?: number
  }

  const features = result.features as {
    domain_age_days?: number | null
    ip_in_url?: boolean
    at_sign?: boolean
    url_length?: number
    subdomain_count?: number
    suspicious_tld?: boolean
    impersonation_patterns?: string[]
  }

  return (
    <div className="max-w-3xl mx-auto px-4 py-10">
      {/* 단축 링크 확장 배너 */}
      {result.is_shortened && result.expanded_url && (
        <div className="bg-blue-950/60 border border-blue-700 rounded-xl px-5 py-4 mb-5 text-sm">
          <div className="flex items-center gap-2 text-blue-300 font-medium mb-2">
            <span>🔗</span> 단축 링크가 감지되어 원본 URL을 검사했습니다
          </div>
          <div className="space-y-1 text-xs">
            <div className="flex items-start gap-2">
              <span className="text-slate-500 shrink-0 w-16">입력 URL</span>
              <span className="font-mono text-slate-400 break-all">{result.input_url}</span>
            </div>
            <div className="flex items-start gap-2">
              <span className="text-blue-400 shrink-0 w-16">원본 URL</span>
              <span className="font-mono text-blue-300 break-all">{result.expanded_url}</span>
            </div>
          </div>
        </div>
      )}

      {/* URL 표시 */}
      <div className="text-slate-500 text-sm mb-6 truncate">
        검사한 URL: <span className="text-slate-300 font-mono">
          {result.is_shortened && result.expanded_url ? result.expanded_url : url}
        </span>
      </div>

      {/* 판정 카드 */}
      <div className={`${cfg.bg} border ${cfg.border} rounded-2xl p-8 mb-6`}>
        <div className="flex items-center justify-between mb-6">
          <div>
            <span className={`inline-block ${cfg.badge} text-sm font-bold px-4 py-1.5 rounded-full mb-3`}>
              {cfg.emoji} {cfg.label}
            </span>
            <h1 className="text-2xl font-bold text-white">
              {verdict === 'dangerous' && '위험한 사이트입니다'}
              {verdict === 'suspicious' && '의심스러운 사이트입니다'}
              {verdict === 'safe' && '안전한 사이트입니다'}
            </h1>
            <p className="text-slate-400 text-sm mt-1">
              {verdict === 'dangerous' && '접속을 즉시 중단하고 개인정보를 입력하지 마세요.'}
              {verdict === 'suspicious' && '주의가 필요합니다. 신중하게 접근하세요.'}
              {verdict === 'safe' && '알려진 위협이 감지되지 않았습니다.'}
            </p>
          </div>
          <div className={`text-5xl font-black ${cfg.text}`}>{result.risk_score}</div>
        </div>

        {/* 위험 점수 바 */}
        <div>
          <div className="flex justify-between text-xs text-slate-400 mb-1">
            <span>위험 점수</span>
            <span>{result.risk_score} / 100</span>
          </div>
          <div className="w-full bg-slate-700 rounded-full h-3">
            <div
              className={`${cfg.bar} h-3 rounded-full transition-all duration-700`}
              style={{ width: `${result.risk_score}%` }}
            />
          </div>
        </div>
      </div>

      {/* 탐지 요약 */}
      <div className="bg-slate-800 border border-slate-700 rounded-xl p-5 mb-4">
        <h2 className="text-sm font-semibold text-slate-400 mb-2 uppercase tracking-wide">탐지 근거</h2>
        <p className="text-slate-200 text-sm leading-relaxed">{result.final_reason}</p>
        {result.decision_type && (
          <span className="inline-block mt-2 text-xs bg-slate-700 text-slate-300 px-2 py-0.5 rounded-md">
            {DECISION_LABELS[result.decision_type] ?? result.decision_type}
          </span>
        )}
      </div>

      {/* 트리거된 규칙 */}
      {ruleInfo.triggered_rules && ruleInfo.triggered_rules.length > 0 && (
        <div className="bg-slate-800 border border-slate-700 rounded-xl p-5 mb-4">
          <h2 className="text-sm font-semibold text-slate-400 mb-3 uppercase tracking-wide">탐지된 위험 패턴</h2>
          <div className="flex flex-wrap gap-2">
            {ruleInfo.triggered_rules.map((r) => (
              <span key={r} className="bg-red-950 text-red-300 border border-red-800 text-xs px-3 py-1 rounded-lg">
                {r}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* URL 특성 */}
      <div className="bg-slate-800 border border-slate-700 rounded-xl p-5 mb-4">
        <h2 className="text-sm font-semibold text-slate-400 mb-4 uppercase tracking-wide">URL 특성 분석</h2>
        <div className="space-y-2.5 text-sm">
          {features.domain_age_days !== undefined && (
            <DetailRow
              label="도메인 나이"
              value={features.domain_age_days != null ? `${features.domain_age_days}일` : '확인 불가'}
              highlight={features.domain_age_days != null && features.domain_age_days < 30}
            />
          )}
          {features.url_length !== undefined && (
            <DetailRow
              label="URL 길이"
              value={`${features.url_length}자`}
              highlight={(features.url_length ?? 0) > 100}
            />
          )}
          {features.subdomain_count !== undefined && (
            <DetailRow
              label="서브도메인 수"
              value={`${features.subdomain_count}개`}
              highlight={(features.subdomain_count ?? 0) > 3}
            />
          )}
          <DetailRow
            label="IP 주소 사용"
            value={features.ip_in_url ? '감지됨' : '정상'}
            highlight={!!features.ip_in_url}
          />
          <DetailRow
            label="@ 기호 포함"
            value={features.at_sign ? '감지됨' : '없음'}
            highlight={!!features.at_sign}
          />
          <DetailRow
            label="의심 TLD"
            value={features.suspicious_tld ? '의심 TLD 사용' : '정상'}
            highlight={!!features.suspicious_tld}
          />
          {features.impersonation_patterns && features.impersonation_patterns.length > 0 && (
            <DetailRow
              label="브랜드 사칭"
              value={features.impersonation_patterns.join(', ')}
              highlight
            />
          )}
        </div>
      </div>

      {/* 외부 API 결과 */}
      <div className="bg-slate-800 border border-slate-700 rounded-xl p-5 mb-6">
        <h2 className="text-sm font-semibold text-slate-400 mb-4 uppercase tracking-wide">외부 API 검사 결과</h2>
        <div className="space-y-2.5 text-sm">
          <DetailRow
            label="Google Safe Browsing"
            value={
              apiResults.safe_browsing?.skipped
                ? 'API 키 미설정 (스킵)'
                : apiResults.safe_browsing?.is_safe
                ? '위협 없음'
                : '위협 탐지됨'
            }
            highlight={apiResults.safe_browsing && !apiResults.safe_browsing.skipped && !apiResults.safe_browsing.is_safe}
          />
          <DetailRow
            label="PhishTank"
            value={
              apiResults.phishtank?.skipped
                ? '스킵 (화이트리스트)'
                : !apiResults.phishtank?.available
                ? '조회 실패'
                : apiResults.phishtank?.is_phishing
                ? '피싱 사이트 확정 (검증됨)'
                : apiResults.phishtank?.in_database && !apiResults.phishtank?.valid
                ? 'DB 등록됨 (만료된 피싱)'
                : 'DB 미등록 (안전)'
            }
            highlight={apiResults.phishtank?.is_phishing}
          />
          {aiResults.url_transformer && (
            <DetailRow
              label="AI 모델 (URLBert)"
              value={
                aiResults.url_transformer.skipped
                  ? '스킵'
                  : `${aiResults.url_transformer.label ?? '-'} (${((aiResults.url_transformer.score ?? 0) * 100).toFixed(1)}%)`
              }
              highlight={aiResults.url_transformer.label === 'malicious'}
            />
          )}
        </div>
      </div>

      {/* 액션 */}
      <div className="flex flex-wrap gap-3 mb-10">
        <Link
          href="/"
          className="flex-1 bg-slate-700 hover:bg-slate-600 text-white text-center py-3 rounded-xl transition-colors font-medium"
        >
          다시 검사하기
        </Link>
        {verdict === 'safe' && !reported && (
          <button
            onClick={handleReport}
            className="flex-1 border border-yellow-600 text-yellow-400 hover:bg-yellow-950 py-3 rounded-xl transition-colors font-medium"
          >
            의심 사이트로 제보
          </button>
        )}
        {reported && (
          <div className="flex-1 border border-green-700 text-green-400 text-center py-3 rounded-xl font-medium">
            제보 완료
          </div>
        )}
      </div>

      {/* 다른 URL 검사 */}
      <form onSubmit={handleRescan} className="flex gap-2">
        <input
          type="text"
          value={newUrl}
          onChange={(e) => setNewUrl(e.target.value)}
          placeholder="다른 URL 검사..."
          className="flex-1 bg-slate-800 border border-slate-600 text-white placeholder-slate-500
                     rounded-lg px-4 py-2.5 text-sm outline-none focus:border-red-500 transition-colors"
        />
        <button
          type="submit"
          className="bg-red-600 hover:bg-red-500 text-white px-6 py-2.5 rounded-lg text-sm font-medium transition-colors"
        >
          검사
        </button>
      </form>
    </div>
  )
}

function DetailRow({ label, value, highlight }: { label: string; value: string; highlight?: boolean | null }) {
  return (
    <div className="flex justify-between items-center py-2 border-b border-slate-700/50 last:border-0">
      <span className="text-slate-400">{label}</span>
      <span className={highlight ? 'text-red-400 font-medium' : 'text-slate-300'}>{value}</span>
    </div>
  )
}

export default function ResultsPage() {
  return (
    <Suspense fallback={<div className="text-center py-20 text-slate-400">불러오는 중...</div>}>
      <ResultContent />
    </Suspense>
  )
}
