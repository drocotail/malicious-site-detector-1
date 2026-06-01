'use client'

import { useEffect, useState } from 'react'
import { getAdminUsers, blockUser, unblockUser, AdminUser, extractAdminError } from '@/lib/adminApi'

function timeAgo(iso: string) {
  const diff = Math.floor((Date.now() - new Date(iso).getTime()) / 1000)
  if (diff < 86400) return `${Math.floor(diff / 3600)}시간 전`
  return `${Math.floor(diff / 86400)}일 전`
}

export default function AdminUsersPage() {
  const [users, setUsers] = useState<AdminUser[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [processingId, setProcessingId] = useState<number | null>(null)
  const [toast, setToast] = useState('')

  useEffect(() => {
    getAdminUsers(0, 200)
      .then(setUsers)
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  const showToast = (msg: string) => {
    setToast(msg)
    setTimeout(() => setToast(''), 3000)
  }

  const handleBlock = async (user: AdminUser) => {
    const action = user.is_blocked ? '차단 해제' : '차단'
    if (!confirm(`'${user.nickname || user.email}' 사용자를 ${action}하시겠습니까?`)) return

    setProcessingId(user.id)
    try {
      const fn = user.is_blocked ? unblockUser : blockUser
      const res = await fn(user.id)
      showToast(res.message)
      setUsers((prev) =>
        prev.map((u) => u.id === user.id ? { ...u, is_blocked: !u.is_blocked } : u)
      )
    } catch (err) {
      showToast(extractAdminError(err, `${action} 중 오류가 발생했습니다.`))
    } finally {
      setProcessingId(null)
    }
  }

  const filtered = search
    ? users.filter((u) => u.email.includes(search) || (u.nickname ?? '').includes(search))
    : users

  const blockedCount = users.filter((u) => u.is_blocked).length

  return (
    <div className="p-8">
      {/* Toast */}
      {toast && (
        <div className="fixed top-6 right-6 bg-slate-800 border border-slate-600 text-white text-sm px-5 py-3 rounded-xl shadow-xl z-50">
          {toast}
        </div>
      )}

      <h1 className="text-2xl font-bold text-white mb-2">사용자 관리</h1>
      <p className="text-slate-500 text-sm mb-6">
        총 {users.length}명 가입
        {blockedCount > 0 && (
          <span className="ml-2 text-red-400">({blockedCount}명 차단 중)</span>
        )}
      </p>

      <input
        type="text"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        placeholder="이메일 또는 닉네임 검색..."
        className="w-full max-w-sm bg-slate-900 border border-slate-800 text-white placeholder-slate-600
                   rounded-lg px-4 py-2.5 text-sm outline-none focus:border-red-500 transition-colors mb-5"
      />

      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        {loading ? (
          <div className="text-center py-16 text-slate-500">불러오는 중...</div>
        ) : filtered.length === 0 ? (
          <div className="text-center py-16 text-slate-500">사용자가 없습니다</div>
        ) : (
          <table className="w-full text-sm">
            <thead className="border-b border-slate-800 bg-slate-900/80">
              <tr>
                {['#', '이메일', '닉네임', '상태', '검사 수', '가입일', ''].map((h) => (
                  <th key={h} className="text-left text-slate-500 font-medium px-4 py-3">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map((u) => (
                <tr
                  key={u.id}
                  className={`border-b border-slate-800/60 last:border-0 transition-colors
                    ${u.is_blocked ? 'bg-red-950/10' : 'hover:bg-slate-800/30'}`}
                >
                  <td className="px-4 py-3 text-slate-600">{u.id}</td>
                  <td className="px-4 py-3 text-slate-300">{u.email}</td>
                  <td className="px-4 py-3 text-slate-400">{u.nickname ?? '-'}</td>
                  <td className="px-4 py-3">
                    {u.is_blocked ? (
                      <span className="text-xs bg-red-950 text-red-300 border border-red-800 px-2 py-0.5 rounded-full">
                        차단됨
                      </span>
                    ) : (
                      <span className="text-xs bg-green-950 text-green-400 border border-green-900 px-2 py-0.5 rounded-full">
                        정상
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-slate-400">{u.scan_count}</td>
                  <td className="px-4 py-3 text-slate-600 text-xs whitespace-nowrap">{timeAgo(u.created_at)}</td>
                  <td className="px-4 py-3">
                    <button
                      onClick={() => handleBlock(u)}
                      disabled={processingId === u.id}
                      className={`text-xs font-medium transition-colors disabled:opacity-40
                        ${u.is_blocked
                          ? 'text-green-500 hover:text-green-300'
                          : 'text-slate-500 hover:text-red-400'
                        }`}
                    >
                      {processingId === u.id ? '...' : u.is_blocked ? '차단 해제' : '차단'}
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
