"""Application configuration, loaded from environment variables (prefix ``TS_``)."""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="TS_", env_file=".env", extra="ignore")

    environment: str = "local"
    # LLM provider cascade for summaries; each reads its own key from the env.
    # When all fail, an extractive summary is used instead.
    llm_spec: str = "anthropic,openai,gemini,deepseek,ollama"
    llm_max_tokens: int = 220


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
