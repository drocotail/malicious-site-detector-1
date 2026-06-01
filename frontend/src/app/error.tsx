'use client'

import { useEffect } from 'react'
import Link from 'next/link'

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  useEffect(() => {
    console.error(error)
  }, [error])

  return (
    <div className="min-h-[70vh] flex flex-col items-center justify-center text-center px-4">
      <div className="text-6xl mb-4">⚠️</div>
      <h1 className="text-3xl font-bold text-white mb-2">오류가 발생했습니다</h1>
      <p className="text-slate-400 mb-8">잠시 후 다시 시도해주세요.</p>
      <div className="flex gap-3">
        <button
          onClick={reset}
          className="bg-red-600 hover:bg-red-500 text-white font-medium px-6 py-3 rounded-xl transition-colors"
        >
          다시 시도
        </button>
        <Link
          href="/"
          className="bg-slate-700 hover:bg-slate-600 text-white font-medium px-6 py-3 rounded-xl transition-colors"
        >
          홈으로
        </Link>
      </div>
    </div>
  )
}
