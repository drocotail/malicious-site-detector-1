'use client'

import { useEffect, useState } from 'react'
import { useRouter, useParams } from 'next/navigation'
import Link from 'next/link'
import { getPost, updatePost, deletePost, extractError, Post } from '@/lib/api'

function formatDate(iso: string) {
  return new Date(iso).toLocaleString('ko-KR', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit',
  })
}

export default function PostDetailPage() {
  const router = useRouter()
  const params = useParams()
  const postId = Number(params.id)

  const [post, setPost] = useState<Post | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  // 수정 모드
  const [editing, setEditing] = useState(false)
  const [editTitle, setEditTitle] = useState('')
  const [editContent, setEditContent] = useState('')
  const [saving, setSaving] = useState(false)
  const [editError, setEditError] = useState('')

  const [myUserId, setMyUserId] = useState<number | null>(null)

  useEffect(() => {
    // JWT에서 user_id 파싱 (payload.sub)
    const token = localStorage.getItem('token')
    if (token) {
      try {
        const payload = JSON.parse(atob(token.split('.')[1]))
        setMyUserId(Number(payload.sub))
      } catch {}
    }

    getPost(postId)
      .then(setPost)
      .catch(() => setError('게시글을 불러올 수 없습니다.'))
      .finally(() => setLoading(false))
  }, [postId])

  const startEdit = () => {
    if (!post) return
    setEditTitle(post.title)
    setEditContent(post.content)
    setEditError('')
    setEditing(true)
  }

  const handleUpdate = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!editTitle.trim() || !editContent.trim()) {
      setEditError('제목과 내용을 모두 입력해주세요.')
      return
    }
    setSaving(true)
    setEditError('')
    try {
      const updated = await updatePost(postId, editTitle.trim(), editContent.trim())
      setPost(updated)
      setEditing(false)
    } catch (err) {
      setEditError(extractError(err, '수정 중 오류가 발생했습니다.'))
    } finally {
      setSaving(false)
    }
  }

  const handleDelete = async () => {
    if (!confirm('게시글을 삭제하시겠습니까?')) return
    try {
      await deletePost(postId)
      router.push('/community')
    } catch (err) {
      alert(extractError(err, '삭제 중 오류가 발생했습니다.'))
    }
  }

  if (loading) {
    return <div className="text-center py-20 text-slate-400">불러오는 중...</div>
  }

  if (error || !post) {
    return (
      <div className="max-w-3xl mx-auto px-4 py-20 text-center">
        <p className="text-red-400 mb-4">{error || '게시글을 찾을 수 없습니다.'}</p>
        <Link href="/community" className="text-slate-400 hover:text-white underline text-sm">
          목록으로
        </Link>
      </div>
    )
  }

  const isOwner = myUserId === post.user_id

  return (
    <div className="max-w-3xl mx-auto px-4 py-10">
      {/* 상단 네비 */}
      <div className="flex items-center gap-2 mb-8">
        <Link href="/community" className="text-slate-400 hover:text-white transition-colors text-sm">
          ← 목록
        </Link>
      </div>

      {editing ? (
        /* 수정 폼 */
        <form onSubmit={handleUpdate} className="space-y-4">
          <input
            type="text"
            value={editTitle}
            onChange={(e) => setEditTitle(e.target.value)}
            maxLength={200}
            className="w-full bg-slate-800 border border-slate-600 text-white placeholder-slate-500
                       rounded-xl px-4 py-3 text-lg font-bold outline-none focus:border-red-500 transition-all"
          />
          <textarea
            value={editContent}
            onChange={(e) => setEditContent(e.target.value)}
            rows={14}
            className="w-full bg-slate-800 border border-slate-600 text-white
                       rounded-xl px-4 py-3 outline-none focus:border-red-500 transition-all resize-none leading-relaxed"
          />
          {editError && (
            <p className="text-red-400 text-sm">{editError}</p>
          )}
          <div className="flex gap-3">
            <button
              type="button"
              onClick={() => setEditing(false)}
              className="flex-1 bg-slate-700 hover:bg-slate-600 text-white py-3 rounded-xl transition-colors"
            >
              취소
            </button>
            <button
              type="submit"
              disabled={saving}
              className="flex-1 bg-red-600 hover:bg-red-500 disabled:bg-slate-700 disabled:text-slate-500 text-white py-3 rounded-xl transition-colors"
            >
              {saving ? '저장 중...' : '저장'}
            </button>
          </div>
        </form>
      ) : (
        /* 게시글 보기 */
        <>
          <div className="bg-slate-800 border border-slate-700 rounded-2xl p-8 mb-6">
            <h1 className="text-2xl font-bold text-white mb-4">{post.title}</h1>

            <div className="flex items-center justify-between pb-4 mb-6 border-b border-slate-700">
              <div className="flex items-center gap-4 text-sm text-slate-400">
                <span className="font-medium text-slate-300">{post.author_nickname}</span>
                <span>{formatDate(post.created_at)}</span>
                {post.updated_at && (
                  <span className="text-slate-600 text-xs">(수정됨)</span>
                )}
              </div>
              <span className="text-xs text-slate-600">조회 {post.view_count}</span>
            </div>

            <div className="text-slate-200 leading-relaxed whitespace-pre-wrap text-sm">
              {post.content}
            </div>
          </div>

          {/* 수정/삭제 버튼 (본인만) */}
          {isOwner && (
            <div className="flex gap-3 mb-6">
              <button
                onClick={startEdit}
                className="bg-slate-700 hover:bg-slate-600 text-white px-6 py-2.5 rounded-xl text-sm font-medium transition-colors"
              >
                수정
              </button>
              <button
                onClick={handleDelete}
                className="border border-red-800 text-red-400 hover:bg-red-950 px-6 py-2.5 rounded-xl text-sm font-medium transition-colors"
              >
                삭제
              </button>
            </div>
          )}

          <Link
            href="/community"
            className="block text-center bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 py-3 rounded-xl text-sm transition-colors"
          >
            목록으로 돌아가기
          </Link>
        </>
      )}
    </div>
  )
}
