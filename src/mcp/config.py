"""MCP server configuration management."""
import os
from typing import Optional
from dataclasses import dataclass


@dataclass
class MCPConfig:
    """MCP server configuration."""
    openai_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    ollama_base_url: str = "http://localhost:11434"
    default_llm_provider: str = "openai"
    default_llm_model: str = "gpt-3.5-turbo"
    max_iterations: int = 5

    @classmethod
    def from_env(cls) -> "MCPConfig":
        """Load configuration from environment variables."""
        return cls(
            openai_api_key=os.getenv("OPENAI_API_KEY"),
            anthropic_api_key=os.getenv("ANTHROPIC_API_KEY"),
            ollama_base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
            default_llm_provider=os.getenv("DEFAULT_LLM_PROVIDER", "openai"),
            default_llm_model=os.getenv("DEFAULT_LLM_MODEL", "gpt-3.5-turbo"),
            max_iterations=int(os.getenv("MAX_ITERATIONS", "5"))
        )
