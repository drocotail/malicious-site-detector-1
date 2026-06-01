'use client'

import { useEffect, useState } from 'react'
import {
  getAdminSites, addAdminSite, updateAdminSite, deleteAdminSite,
  AdminSite, extractAdminError,
} from '@/lib/adminApi'

const CATEGORY_LABELS: Record<string, string> = {
  confirmed_phishing: '확정 피싱',
  suspicious: '의심',
  malware: '악성코드',
  user_reported: '제보',
}
const CATEGORY_COLORS: Record<string, string> = {
  confirmed_phishing: 'bg-red-950 text-red-300 border-red-800',
  suspicious: 'bg-yellow-950 text-yellow-300 border-yellow-800',
  malware: 'bg-orange-950 text-orange-300 border-orange-800',
  user_reported: 'bg-blue-950 text-blue-300 border-blue-800',
}

function timeAgo(iso: string) {
  const diff = Math.floor((Date.now() - new Date(iso).getTime()) / 1000)
  if (diff < 3600) return `${Math.floor(diff / 60)}분 전`
  if (diff < 86400) return `${Math.floor(diff / 3600)}시간 전`
  return `${Math.floor(diff / 86400)}일 전`
}

export default function AdminSitesPage() {
  const [sites, setSites] = useState<AdminSite[]>([])
  const [loading, setLoading] = useState(true)
  const [showAdd, setShowAdd] = useState(false)
  const [form, setForm] = useState({ url: '', domain: '', category: 'confirmed_phishing', threat_types: '' })
  const [formError, setFormError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  const load = () => {
    setLoading(true)
    getAdminSites(0, 100)
      .then(setSites)
      .catch(() => {})
      .finally(() => setLoading(false))
  }

  useEffect(load, [])

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!form.url.trim() || !form.domain.trim()) { setFormError('URL과 도메인을 입력해주세요.'); return }
    setSubmitting(true)
    setFormError('')
    try {
      await addAdminSite({
        url: form.url.trim(),
        domain: form.domain.trim(),
        category: form.category,
        threat_types: form.threat_types.split(',').map((t) => t.trim()).filter(Boolean),
      })
      setForm({ url: '', domain: '', category: 'confirmed_phishing', threat_types: '' })
      setShowAdd(false)
      load()
    } catch (err) {
      setFormError(extractAdminError(err, '등록에 실패했습니다.'))
    } finally {
      setSubmitting(false)
    }
  }

  const handleCategoryChange = async (id: number, category: string) => {
    await updateAdminSite(id, category)
    setSites((prev) => prev.map((s) => s.id === id ? { ...s, category } : s))
  }

  const handleDelete = async (id: number) => {
    if (!confirm('삭제하시겠습니까?')) return
    await deleteAdminSite(id)
    setSites((prev) => prev.filter((s) => s.id !== id))
  }

  return (
    <div className="p-8">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white">악성 사이트 관리</h1>
          <p className="text-slate-500 text-sm mt-1">총 {sites.length}개 등록됨</p>
        </div>
        <button
          onClick={() => { setShowAdd(!showAdd); setFormError('') }}
          className="bg-red-600 hover:bg-red-500 text-white text-sm font-medium px-5 py-2.5 rounded-xl transition-colors"
        >
          + 사이트 추가
        </button>
      </div>

      {showAdd && (
        <form onSubmit={handleAdd} className="bg-slate-900 border border-slate-700 rounded-xl p-5 mb-6 space-y-3">
          <h2 className="text-sm font-semibold text-slate-300">새 악성 사이트 등록</h2>
          <div className="grid grid-cols-2 gap-3">
            <input
              placeholder="URL (https://...)"
              value={form.url}
              onChange={(e) => setForm({ ...form, url: e.target.value })}
              className="bg-slate-800 border border-slate-700 text-white placeholder-slate-500 rounded-lg px-3 py-2 text-sm outline-none focus:border-red-500"
            />
            <input
              placeholder="도메인 (example.com)"
              value={form.domain}
              onChange={(e) => setForm({ ...form, domain: e.target.value })}
              className="bg-slate-800 border border-slate-700 text-white placeholder-slate-500 rounded-lg px-3 py-2 text-sm outline-none focus:border-red-500"
            />
            <select
              value={form.category}
              onChange={(e) => setForm({ ...form, category: e.target.value })}
              className="bg-slate-800 border border-slate-700 text-white rounded-lg px-3 py-2 text-sm outline-none focus:border-red-500"
            >
              <option value="confirmed_phishing">확정 피싱</option>
              <option value="suspicious">의심</option>
              <option value="malware">악성코드</option>
            </select>
            <input
              placeholder="위협 유형 (쉼표 구분)"
              value={form.threat_types}
              onChange={(e) => setForm({ ...form, threat_types: e.target.value })}
              className="bg-slate-800 border border-slate-700 text-white placeholder-slate-500 rounded-lg px-3 py-2 text-sm outline-none focus:border-red-500"
            />
          </div>
          {formError && <p className="text-red-400 text-sm">{formError}</p>}
          <div className="flex gap-2">
            <button
              type="submit"
              disabled={submitting}
              className="bg-red-600 hover:bg-red-500 disabled:bg-slate-700 text-white text-sm px-5 py-2 rounded-lg transition-colors"
            >
              {submitting ? '등록 중...' : '등록'}
            </button>
            <button
              type="button"
              onClick={() => setShowAdd(false)}
              className="bg-slate-700 hover:bg-slate-600 text-white text-sm px-5 py-2 rounded-lg transition-colors"
            >
              취소
            </button>
          </div>
        </form>
      )}

      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        {loading ? (
          <div className="text-center py-16 text-slate-500">불러오는 중...</div>
        ) : sites.length === 0 ? (
          <div className="text-center py-16 text-slate-500">등록된 사이트가 없습니다</div>
        ) : (
          <table className="w-full text-sm">
            <thead className="border-b border-slate-800 bg-slate-900/80">
              <tr>
                {['도메인', '분류', '위협 유형', '출처', '등록일', ''].map((h) => (
                  <th key={h} className="text-left text-slate-500 font-medium px-4 py-3">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {sites.map((s) => (
                <tr key={s.id} className="border-b border-slate-800/60 last:border-0 hover:bg-slate-800/30">
                  <td className="px-4 py-3 font-mono text-slate-300 max-w-[180px] truncate">{s.domain}</td>
                  <td className="px-4 py-3">
                    <select
                      value={s.category}
                      onChange={(e) => handleCategoryChange(s.id, e.target.value)}
                      className={`text-xs border rounded-md px-2 py-1 bg-transparent outline-none cursor-pointer
                        ${CATEGORY_COLORS[s.category] ?? 'bg-slate-800 text-slate-300 border-slate-700'}`}
                    >
                      <option value="confirmed_phishing">확정 피싱</option>
                      <option value="suspicious">의심</option>
                      <option value="malware">악성코드</option>
                      <option value="user_reported">제보</option>
                    </select>
                  </td>
                  <td className="px-4 py-3 text-slate-500 text-xs max-w-[160px] truncate">
                    {s.threat_types?.join(', ') || '-'}
                  </td>
                  <td className="px-4 py-3 text-slate-500 text-xs">{s.source}</td>
                  <td className="px-4 py-3 text-slate-600 text-xs whitespace-nowrap">{timeAgo(s.created_at)}</td>
                  <td className="px-4 py-3">
                    <button
                      onClick={() => handleDelete(s.id)}
                      className="text-slate-600 hover:text-red-400 transition-colors text-xs"
                    >
                      삭제
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
