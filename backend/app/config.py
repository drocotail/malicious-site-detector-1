from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql://postgres:password@localhost:5432/malicious_sites"
    secret_key: str = "change-this-to-a-long-random-secret-key"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    google_safe_browsing_api_key: str = ""
    virustotal_api_key: str = ""
    phishtank_app_key: str = ""
    gmail_user: str = ""
    gmail_app_password: str = ""

    class Config:
        env_file = ".env"


settings = Settings()
