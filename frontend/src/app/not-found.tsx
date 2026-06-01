import Link from 'next/link'

export default function NotFound() {
  return (
    <div className="min-h-[70vh] flex flex-col items-center justify-center text-center px-4">
      <div className="text-6xl mb-4">🔍</div>
      <h1 className="text-3xl font-bold text-white mb-2">페이지를 찾을 수 없습니다</h1>
      <p className="text-slate-400 mb-8">요청하신 페이지가 존재하지 않습니다.</p>
      <Link
        href="/"
        className="bg-red-600 hover:bg-red-500 text-white font-medium px-6 py-3 rounded-xl transition-colors"
      >
        홈으로 돌아가기
      </Link>
    </div>
  )
}
