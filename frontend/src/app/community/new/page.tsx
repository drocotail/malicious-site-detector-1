'use client'

import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { createPost, extractError } from '@/lib/api'

export default function NewPostPage() {
  const router = useRouter()
  const [title, setTitle] = useState('')
  const [content, setContent] = useState('')
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  useEffect(() => {
    if (!localStorage.getItem('token')) router.push('/auth/login')
  }, [router])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!title.trim() || !content.trim()) {
      setError('제목과 내용을 모두 입력해주세요.')
      return
    }
    setSubmitting(true)
    setError('')
    try {
      const post = await createPost(title.trim(), content.trim())
      router.push(`/community/${post.id}`)
    } catch (err) {
      setError(extractError(err, '게시글 작성 중 오류가 발생했습니다.'))
      setSubmitting(false)
    }
  }

  return (
    <div className="max-w-3xl mx-auto px-4 py-10">
      <div className="flex items-center gap-3 mb-8">
        <button
          onClick={() => router.back()}
          className="text-slate-400 hover:text-white transition-colors text-sm"
        >
          ← 뒤로
        </button>
        <h1 className="text-2xl font-bold text-white">새 글 작성</h1>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm text-slate-400 mb-1.5">제목</label>
          <input
            type="text"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="제목을 입력하세요"
            maxLength={200}
            className="w-full bg-slate-800 border border-slate-600 text-white placeholder-slate-500
                       rounded-xl px-4 py-3 outline-none focus:border-red-500 focus:ring-1 focus:ring-red-500/30 transition-all"
          />
          <div className="text-right text-xs text-slate-600 mt-1">{title.length}/200</div>
        </div>

        <div>
          <label className="block text-sm text-slate-400 mb-1.5">내용</label>
          <textarea
            value={content}
            onChange={(e) => setContent(e.target.value)}
            placeholder="내용을 입력하세요&#10;&#10;피싱 사이트 제보, 보안 정보, 주의사항 등을 공유해주세요."
            rows={14}
            className="w-full bg-slate-800 border border-slate-600 text-white placeholder-slate-500
                       rounded-xl px-4 py-3 outline-none focus:border-red-500 focus:ring-1 focus:ring-red-500/30 transition-all resize-none leading-relaxed"
          />
        </div>

        {error && (
          <p className="text-red-400 text-sm bg-red-950/50 border border-red-800 rounded-lg px-4 py-2">
            {error}
          </p>
        )}

        <div className="flex gap-3 pt-2">
          <button
            type="button"
            onClick={() => router.back()}
            className="flex-1 bg-slate-700 hover:bg-slate-600 text-white py-3 rounded-xl transition-colors font-medium"
          >
            취소
          </button>
          <button
            type="submit"
            disabled={submitting}
            className="flex-1 bg-red-600 hover:bg-red-500 disabled:bg-slate-700 disabled:text-slate-500
                       text-white py-3 rounded-xl transition-colors font-medium"
          >
            {submitting ? '등록 중...' : '게시글 등록'}
          </button>
        </div>
      </form>
    </div>
  )
}
