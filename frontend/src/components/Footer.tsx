export default function Footer() {
  return (
    <footer className="mt-24 border-t border-slate-800 bg-slate-900/50">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 py-8 flex flex-col sm:flex-row items-center justify-between gap-4 text-sm text-slate-500">
        <div className="flex items-center gap-2">
          <span className="text-red-500 text-base">&#9673;</span>
          <span>MaliciousScan &mdash; 실시간 피싱 사이트 탐지</span>
        </div>
        <p>&copy; {new Date().getFullYear()} MaliciousScan. All rights reserved.</p>
      </div>
    </footer>
  )
}
