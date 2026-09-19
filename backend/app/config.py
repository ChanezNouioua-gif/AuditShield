from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    app_name: str = "AuditShield"
    database_url: str
    openai_api_key: str
    chroma_persist_dir: str = "./chroma_data"

    class Config:
        env_file = ".env"

settings = Settings()