"""LLM provider registry and management."""
from typing import Dict, Type, Optional
from .base import BaseLLMProvider, LLMProvider, LLMConfig
from .openai_provider import OpenAIProvider
from .anthropic_provider import AnthropicProvider
from .ollama_provider import OllamaProvider


class LLMRegistry:
    """Registry for LLM providers."""

    _providers: Dict[LLMProvider, Type[BaseLLMProvider]] = {
        LLMProvider.OPENAI: OpenAIProvider,
        LLMProvider.ANTHROPIC: AnthropicProvider,
        LLMProvider.OLLAMA: OllamaProvider,
    }

    @classmethod
    def register(cls, provider: LLMProvider, provider_class: Type[BaseLLMProvider]) -> None:
        """Register a new LLM provider."""
        cls._providers[provider] = provider_class

    @classmethod
    def get_provider(cls, config: LLMConfig) -> BaseLLMProvider:
        """Get LLM provider instance from config."""
        provider_class = cls._providers.get(config.provider)
        if not provider_class:
            raise ValueError(f"Unknown provider: {config.provider}")
        return provider_class(config)

    @classmethod
    def list_providers(cls) -> list[str]:
        """List all registered providers."""
        return [p.value for p in cls._providers.keys()]


class LLMManager:
    """Manager for LLM provider instances with caching."""

    def __init__(self):
        self._instances: Dict[str, BaseLLMProvider] = {}

    def get_or_create(self, config: LLMConfig) -> BaseLLMProvider:
        """Get or create LLM provider instance."""
        key = f"{config.provider}:{config.model}"

        if key not in self._instances:
            self._instances[key] = LLMRegistry.get_provider(config)

        return self._instances[key]

    async def close_all(self) -> None:
        """Close all provider instances."""
        for instance in self._instances.values():
            if hasattr(instance, '__aexit__'):
                await instance.__aexit__(None, None, None)
        self._instances.clear()
