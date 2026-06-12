# Malicious Site Detector

URL을 입력하면 피싱·악성코드 등 위험 사이트 여부를 탐지하고, 실시간 위협 현황과 사용자 제보를 확인할 수 있는 웹 서비스입니다.

🔗 **Live Demo**: https://malicious-site-detector-1.vercel.app

## 주요 기능

- **URL 검사**: URL을 입력하면 머신러닝 모델과 외부 위협 정보(Google Safe Browsing 등)를 기반으로 위험도를 분석
- **실시간 위협 현황**: 최근 탐지된 위협 사이트 목록과 통계 대시보드
- **사용자 제보**: 의심 사이트를 직접 제보하고 커뮤니티 게시판에서 정보 공유
- **회원 인증**: 이메일 인증 기반 회원가입/로그인
- **관리자 페이지**: 제보 검토, 사이트/사용자 관리, 통계 조회

## 기술 스택

### Frontend
- Next.js 16 (App Router)
- React 18, TypeScript
- Tailwind CSS
- Axios

### Backend
- FastAPI
- SQLAlchemy + PostgreSQL
- JWT 기반 인증 (python-jose, passlib)
- slowapi (요청 속도 제한)
- scikit-learn 기반 피싱 탐지 ML 모델

### Infra
- Docker / Docker Compose
- Render (Backend), Netlify/Vercel (Frontend)

## 프로젝트 구조

```
.
├── backend/        # FastAPI 서버, ML 모델, DB 모델/라우터
├── frontend/        # Next.js 프론트엔드
├── docker-compose.yml
├── render.yaml      # 백엔드 배포 설정
└── netlify.toml     # 프론트엔드 배포 설정
```

## API 개요

| 영역 | 엔드포인트 | 설명 |
| --- | --- | --- |
| 검사 | `POST /api/scan` | URL 위험도 검사 |
| 검사 | `GET /api/sites`, `GET /api/scan/recent-threats` | 위협 사이트 목록/최근 위협 |
| 검사 | `POST /api/reports` | 사용자 제보 |
| 인증 | `POST /api/auth/register`, `/auth/login` 등 | 회원가입/로그인/이메일 인증 |
| 대시보드 | `GET /api/dashboard/history`, `/stats` | 사용자별 검사 기록/통계 |
| 게시판 | `/posts` | 제보/정보 공유 게시판 CRUD |
| 관리자 | `/admin/*` | 제보 검토, 사이트·사용자·게시글 관리 |

## 로컬 실행 (Docker Compose)

```bash
docker compose up --build
```

- Frontend: http://localhost:3000
- Backend: http://localhost:8000

백엔드 실행을 위해 `backend/.env`에 다음과 같은 환경 변수가 필요합니다.

```env
DATABASE_URL=...
SECRET_KEY=...
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
GMAIL_USER=...
GMAIL_APP_PASSWORD=...
GOOGLE_SAFE_BROWSING_API_KEY=...
FRONTEND_URL=...
```

## 배포

- Frontend: Netlify / Vercel (`netlify.toml`)
- Backend: Render (`render.yaml`)
