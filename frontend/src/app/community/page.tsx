'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { getPosts, Post } from '@/lib/api'

function timeAgo(iso: string): string {
  const diff = Math.floor((Date.now() - new Date(iso).getTime()) / 1000)
  if (diff < 60) return `${diff}초 전`
  if (diff < 3600) return `${Math.floor(diff / 60)}분 전`
  if (diff < 86400) return `${Math.floor(diff / 3600)}시간 전`
  return `${Math.floor(diff / 86400)}일 전`
}

export default function CommunityPage() {
  const [posts, setPosts] = useState<Post[]>([])
  const [loading, setLoading] = useState(true)
  const [isLoggedIn, setIsLoggedIn] = useState(false)

  useEffect(() => {
    setIsLoggedIn(!!localStorage.getItem('token'))
    getPosts()
      .then(setPosts)
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  return (
    <div className="max-w-4xl mx-auto px-4 py-10">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-white">커뮤니티</h1>
          <p className="text-slate-400 text-sm mt-1">피싱 사이트 정보를 공유하는 게시판입니다</p>
        </div>
        <Link
          href={isLoggedIn ? '/community/new' : '/auth/login'}
          className="bg-red-600 hover:bg-red-500 text-white text-sm font-medium px-5 py-2.5 rounded-xl transition-colors"
        >
          글쓰기
        </Link>
      </div>

      {loading ? (
        <div className="text-center py-20 text-slate-400">불러오는 중...</div>
      ) : posts.length === 0 ? (
        <div className="bg-slate-800 border border-slate-700 rounded-xl p-16 text-center">
          <div className="text-4xl mb-4">📋</div>
          <p className="text-slate-400 mb-2">아직 게시글이 없습니다</p>
          {isLoggedIn ? (
            <Link href="/community/new" className="text-red-400 hover:underline text-sm">
              첫 번째 글을 작성해보세요
            </Link>
          ) : (
            <Link href="/auth/login" className="text-red-400 hover:underline text-sm">
              로그인 후 글을 작성할 수 있습니다
            </Link>
          )}
        </div>
      ) : (
        <div className="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead className="border-b border-slate-700 bg-slate-800/80">
              <tr>
                <th className="text-left text-slate-400 font-medium px-5 py-3 w-12">번호</th>
                <th className="text-left text-slate-400 font-medium px-5 py-3">제목</th>
                <th className="text-left text-slate-400 font-medium px-5 py-3 w-28">작성자</th>
                <th className="text-left text-slate-400 font-medium px-5 py-3 w-20 text-center">조회</th>
                <th className="text-left text-slate-400 font-medium px-5 py-3 w-28">작성일</th>
              </tr>
            </thead>
            <tbody>
              {posts.map((post) => (
                <tr
                  key={post.id}
                  className="border-b border-slate-700/50 last:border-0 hover:bg-slate-700/30 transition-colors"
                >
                  <td className="px-5 py-3.5 text-slate-500">{post.id}</td>
                  <td className="px-5 py-3.5">
                    <Link
                      href={`/community/${post.id}`}
                      className="text-slate-200 hover:text-white font-medium hover:underline"
                    >
                      {post.title}
                    </Link>
                  </td>
                  <td className="px-5 py-3.5 text-slate-400">{post.author_nickname}</td>
                  <td className="px-5 py-3.5 text-slate-500 text-center">{post.view_count}</td>
                  <td className="px-5 py-3.5 text-slate-500">{timeAgo(post.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
