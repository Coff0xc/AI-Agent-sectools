"""Configuration utilities."""
import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


class LLMProviderConfig(BaseModel):
    """LLM provider configuration."""
    api_key: Optional[str] = None
    model: str
    temperature: float = 0.7
    max_tokens: int = 4000
    timeout: int = 60
    base_url: Optional[str] = None


class LLMSettings(BaseModel):
    """LLM settings."""
    default_provider: str = "openai"
    openai: LLMProviderConfig
    anthropic: LLMProviderConfig
    ollama: LLMProviderConfig


class Config(BaseSettings):
    """Application configuration."""
    llm: Optional[LLMSettings] = None

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


def load_yaml_config(config_path: str) -> Dict[str, Any]:
    """Load YAML configuration file."""
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    # Replace environment variables
    return _replace_env_vars(config)


def _replace_env_vars(obj: Any) -> Any:
    """Recursively replace ${VAR} with environment variables."""
    if isinstance(obj, dict):
        return {k: _replace_env_vars(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_replace_env_vars(item) for item in obj]
    elif isinstance(obj, str) and obj.startswith("${") and obj.endswith("}"):
        var_name = obj[2:-1]
        return os.getenv(var_name, obj)
    return obj


def get_config_path(filename: str) -> Path:
    """Get configuration file path."""
    # Try current directory first
    current_dir = Path.cwd() / "config" / filename
    if current_dir.exists():
        return current_dir

    # Try parent directory
    parent_dir = Path.cwd().parent / "config" / filename
    if parent_dir.exists():
        return parent_dir

    # Default to current directory
    return current_dir
