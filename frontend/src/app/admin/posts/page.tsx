'use client'

import { useEffect, useState } from 'react'
import { getAdminPosts, deleteAdminPost, AdminPost } from '@/lib/adminApi'
import Link from 'next/link'

function timeAgo(iso: string) {
  const diff = Math.floor((Date.now() - new Date(iso).getTime()) / 1000)
  if (diff < 3600) return `${Math.floor(diff / 60)}분 전`
  if (diff < 86400) return `${Math.floor(diff / 3600)}시간 전`
  return `${Math.floor(diff / 86400)}일 전`
}

export default function AdminPostsPage() {
  const [posts, setPosts] = useState<AdminPost[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')

  useEffect(() => {
    getAdminPosts(0, 200)
      .then(setPosts)
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  const handleDelete = async (id: number, title: string) => {
    if (!confirm(`"${title}" 게시글을 삭제하시겠습니까?`)) return
    try {
      await deleteAdminPost(id)
      setPosts((prev) => prev.filter((p) => p.id !== id))
    } catch {}
  }

  const filtered = search
    ? posts.filter((p) =>
        p.title.includes(search) || p.author_nickname.includes(search)
      )
    : posts

  return (
    <div className="p-8">
      <h1 className="text-2xl font-bold text-white mb-2">게시글 관리</h1>
      <p className="text-slate-500 text-sm mb-6">총 {posts.length}개</p>

      <input
        type="text"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        placeholder="제목 또는 작성자 검색..."
        className="w-full max-w-sm bg-slate-900 border border-slate-800 text-white placeholder-slate-600
                   rounded-lg px-4 py-2.5 text-sm outline-none focus:border-red-500 transition-colors mb-5"
      />

      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        {loading ? (
          <div className="text-center py-16 text-slate-500">불러오는 중...</div>
        ) : filtered.length === 0 ? (
          <div className="text-center py-16 text-slate-500">게시글이 없습니다</div>
        ) : (
          <table className="w-full text-sm">
            <thead className="border-b border-slate-800 bg-slate-900/80">
              <tr>
                {['#', '제목', '작성자', '조회수', '작성일', ''].map((h) => (
                  <th key={h} className="text-left text-slate-500 font-medium px-4 py-3">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map((p) => (
                <tr key={p.id} className="border-b border-slate-800/60 last:border-0 hover:bg-slate-800/30">
                  <td className="px-4 py-3 text-slate-600">{p.id}</td>
                  <td className="px-4 py-3 max-w-[280px]">
                    <Link
                      href={`/community/${p.id}`}
                      target="_blank"
                      className="text-slate-300 hover:text-white hover:underline truncate block"
                    >
                      {p.title}
                    </Link>
                  </td>
                  <td className="px-4 py-3 text-slate-400">{p.author_nickname}</td>
                  <td className="px-4 py-3 text-slate-500">{p.view_count}</td>
                  <td className="px-4 py-3 text-slate-600 text-xs whitespace-nowrap">{timeAgo(p.created_at)}</td>
                  <td className="px-4 py-3">
                    <button
                      onClick={() => handleDelete(p.id, p.title)}
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
