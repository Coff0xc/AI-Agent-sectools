"""Ollama (local models) LLM provider implementation."""
import json
from typing import AsyncIterator, Dict, Any
import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from .base import BaseLLMProvider, LLMResponse, LLMConfig


class OllamaProvider(BaseLLMProvider):
    """Ollama local LLM provider."""

    def __init__(self, config: LLMConfig):
        super().__init__(config)
        self.base_url = config.base_url or "http://localhost:11434"
        self._client = httpx.AsyncClient(timeout=config.timeout)

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=60))
    async def generate(self, prompt: str, **kwargs) -> LLMResponse:
        """Generate text from prompt."""
        response = await self._client.post(
            f"{self.base_url}/api/generate",
            json={
                "model": self.config.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": kwargs.get("temperature", self.config.temperature),
                    "num_predict": kwargs.get("max_tokens", self.config.max_tokens),
                }
            }
        )
        response.raise_for_status()
        data = response.json()

        return LLMResponse(
            content=data["response"],
            model=self.config.model,
            tokens_used=data.get("eval_count", 0) + data.get("prompt_eval_count", 0),
            cost=0.0,  # Local models have no API cost
            metadata={
                "eval_count": data.get("eval_count", 0),
                "prompt_eval_count": data.get("prompt_eval_count", 0),
            }
        )

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=60))
    async def generate_structured(self, prompt: str, schema: Dict[str, Any]) -> Dict[str, Any]:
        """Generate structured output matching schema."""
        enhanced_prompt = f"{prompt}\n\nRespond with valid JSON matching this schema: {json.dumps(schema)}"

        response = await self._client.post(
            f"{self.base_url}/api/generate",
            json={
                "model": self.config.model,
                "prompt": enhanced_prompt,
                "stream": False,
                "format": "json",
                "options": {
                    "temperature": self.config.temperature,
                    "num_predict": self.config.max_tokens,
                }
            }
        )
        response.raise_for_status()
        data = response.json()

        content = data["response"]
        return json.loads(content)

    async def stream(self, prompt: str, **kwargs) -> AsyncIterator[str]:
        """Stream generated text."""
        async with self._client.stream(
            "POST",
            f"{self.base_url}/api/generate",
            json={
                "model": self.config.model,
                "prompt": prompt,
                "stream": True,
                "options": {
                    "temperature": kwargs.get("temperature", self.config.temperature),
                    "num_predict": kwargs.get("max_tokens", self.config.max_tokens),
                }
            }
        ) as response:
            response.raise_for_status()
            async for line in response.aiter_lines():
                if line:
                    data = json.loads(line)
                    if "response" in data:
                        yield data["response"]

    def estimate_cost(self, tokens: int) -> float:
        """Estimate cost for token usage."""
        return 0.0  # Local models have no API cost

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self._client.aclose()
