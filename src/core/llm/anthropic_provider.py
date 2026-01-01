"""Anthropic (Claude) LLM provider implementation."""
import json
from typing import AsyncIterator, Dict, Any
from anthropic import AsyncAnthropic
from tenacity import retry, stop_after_attempt, wait_exponential

from .base import BaseLLMProvider, LLMResponse, LLMConfig


class AnthropicProvider(BaseLLMProvider):
    """Anthropic Claude LLM provider."""

    # Pricing per 1M tokens (as of 2024)
    PRICING = {
        "claude-3-opus": {"input": 15.0, "output": 75.0},
        "claude-3-sonnet": {"input": 3.0, "output": 15.0},
        "claude-3-haiku": {"input": 0.25, "output": 1.25},
    }

    def __init__(self, config: LLMConfig):
        super().__init__(config)
        self._client = AsyncAnthropic(
            api_key=config.api_key,
            timeout=config.timeout
        )

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=60))
    async def generate(self, prompt: str, **kwargs) -> LLMResponse:
        """Generate text from prompt."""
        response = await self._client.messages.create(
            model=self.config.model,
            max_tokens=kwargs.get("max_tokens", self.config.max_tokens),
            temperature=kwargs.get("temperature", self.config.temperature),
            messages=[{"role": "user", "content": prompt}]
        )

        tokens_used = response.usage.input_tokens + response.usage.output_tokens
        cost = self.estimate_cost(tokens_used)

        return LLMResponse(
            content=response.content[0].text,
            model=self.config.model,
            tokens_used=tokens_used,
            cost=cost,
            metadata={
                "stop_reason": response.stop_reason,
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens
            }
        )

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=60))
    async def generate_structured(self, prompt: str, schema: Dict[str, Any]) -> Dict[str, Any]:
        """Generate structured output matching schema."""
        enhanced_prompt = f"{prompt}\n\nRespond with valid JSON matching this schema: {json.dumps(schema)}"

        response = await self._client.messages.create(
            model=self.config.model,
            max_tokens=self.config.max_tokens,
            temperature=self.config.temperature,
            messages=[{"role": "user", "content": enhanced_prompt}]
        )

        content = response.content[0].text
        # Extract JSON from markdown code blocks if present
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0].strip()
        elif "```" in content:
            content = content.split("```")[1].split("```")[0].strip()

        return json.loads(content)

    async def stream(self, prompt: str, **kwargs) -> AsyncIterator[str]:
        """Stream generated text."""
        async with self._client.messages.stream(
            model=self.config.model,
            max_tokens=kwargs.get("max_tokens", self.config.max_tokens),
            temperature=kwargs.get("temperature", self.config.temperature),
            messages=[{"role": "user", "content": prompt}]
        ) as stream:
            async for text in stream.text_stream:
                yield text

    def estimate_cost(self, tokens: int) -> float:
        """Estimate cost for token usage."""
        model_base = "-".join(self.config.model.split("-")[0:3])

        if model_base in self.PRICING:
            # Rough estimate: 75% input, 25% output
            input_tokens = int(tokens * 0.75)
            output_tokens = int(tokens * 0.25)
            cost = (input_tokens / 1_000_000 * self.PRICING[model_base]["input"] +
                   output_tokens / 1_000_000 * self.PRICING[model_base]["output"])
            return round(cost, 6)
        return 0.0
