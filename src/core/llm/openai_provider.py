"""OpenAI LLM provider implementation."""
import json
from typing import AsyncIterator, Dict, Any
from openai import AsyncOpenAI
from tenacity import retry, stop_after_attempt, wait_exponential

from .base import BaseLLMProvider, LLMResponse, LLMConfig


class OpenAIProvider(BaseLLMProvider):
    """OpenAI LLM provider."""

    # Pricing per 1K tokens (as of 2024)
    PRICING = {
        "gpt-4": {"input": 0.03, "output": 0.06},
        "gpt-4-turbo": {"input": 0.01, "output": 0.03},
        "gpt-3.5-turbo": {"input": 0.0005, "output": 0.0015},
    }

    def __init__(self, config: LLMConfig):
        super().__init__(config)
        self._client = AsyncOpenAI(
            api_key=config.api_key,
            timeout=config.timeout
        )

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=60))
    async def generate(self, prompt: str, **kwargs) -> LLMResponse:
        """Generate text from prompt."""
        response = await self._client.chat.completions.create(
            model=self.config.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=kwargs.get("temperature", self.config.temperature),
            max_tokens=kwargs.get("max_tokens", self.config.max_tokens),
        )

        tokens_used = response.usage.total_tokens
        cost = self.estimate_cost(tokens_used)

        return LLMResponse(
            content=response.choices[0].message.content,
            model=self.config.model,
            tokens_used=tokens_used,
            cost=cost,
            metadata={"finish_reason": response.choices[0].finish_reason}
        )

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=60))
    async def generate_structured(self, prompt: str, schema: Dict[str, Any]) -> Dict[str, Any]:
        """Generate structured output matching schema."""
        response = await self._client.chat.completions.create(
            model=self.config.model,
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens,
        )

        return json.loads(response.choices[0].message.content)

    async def stream(self, prompt: str, **kwargs) -> AsyncIterator[str]:
        """Stream generated text."""
        stream = await self._client.chat.completions.create(
            model=self.config.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=kwargs.get("temperature", self.config.temperature),
            max_tokens=kwargs.get("max_tokens", self.config.max_tokens),
            stream=True,
        )

        async for chunk in stream:
            if chunk.choices[0].delta.content:
                yield chunk.choices[0].delta.content

    def estimate_cost(self, tokens: int) -> float:
        """Estimate cost for token usage."""
        model_base = self.config.model.split("-")[0:2]
        model_key = "-".join(model_base)

        if model_key in self.PRICING:
            # Rough estimate: 75% input, 25% output
            input_tokens = int(tokens * 0.75)
            output_tokens = int(tokens * 0.25)
            cost = (input_tokens / 1000 * self.PRICING[model_key]["input"] +
                   output_tokens / 1000 * self.PRICING[model_key]["output"])
            return round(cost, 6)
        return 0.0
