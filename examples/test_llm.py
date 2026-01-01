"""Example usage of LLM providers."""
import asyncio
import os
from src.core.llm import LLMProvider, LLMConfig
from src.core.llm.registry import LLMRegistry


async def test_openai():
    """Test OpenAI provider."""
    config = LLMConfig(
        provider=LLMProvider.OPENAI,
        model="gpt-3.5-turbo",
        api_key=os.getenv("OPENAI_API_KEY"),
        temperature=0.7,
        max_tokens=100
    )

    provider = LLMRegistry.get_provider(config)

    async with provider:
        # Test basic generation
        response = await provider.generate("What is penetration testing?")
        print(f"Response: {response.content}")
        print(f"Tokens: {response.tokens_used}, Cost: ${response.cost}")

        # Test structured output
        schema = {
            "type": "object",
            "properties": {
                "definition": {"type": "string"},
                "key_steps": {"type": "array", "items": {"type": "string"}}
            }
        }
        structured = await provider.generate_structured(
            "Define penetration testing and list 3 key steps",
            schema
        )
        print(f"Structured: {structured}")


async def test_anthropic():
    """Test Anthropic provider."""
    config = LLMConfig(
        provider=LLMProvider.ANTHROPIC,
        model="claude-3-haiku-20240307",
        api_key=os.getenv("ANTHROPIC_API_KEY"),
        temperature=0.7,
        max_tokens=100
    )

    provider = LLMRegistry.get_provider(config)

    async with provider:
        response = await provider.generate("What is SQL injection?")
        print(f"Response: {response.content}")
        print(f"Tokens: {response.tokens_used}, Cost: ${response.cost}")


async def test_ollama():
    """Test Ollama provider."""
    config = LLMConfig(
        provider=LLMProvider.OLLAMA,
        model="llama2",
        base_url="http://localhost:11434",
        temperature=0.7,
        max_tokens=100
    )

    provider = LLMRegistry.get_provider(config)

    async with provider:
        response = await provider.generate("What is XSS?")
        print(f"Response: {response.content}")
        print(f"Tokens: {response.tokens_used}, Cost: ${response.cost}")


async def test_streaming():
    """Test streaming generation."""
    config = LLMConfig(
        provider=LLMProvider.OPENAI,
        model="gpt-3.5-turbo",
        api_key=os.getenv("OPENAI_API_KEY")
    )

    provider = LLMRegistry.get_provider(config)

    async with provider:
        print("Streaming response:")
        async for chunk in provider.stream("Explain OWASP Top 10 briefly"):
            print(chunk, end="", flush=True)
        print()


if __name__ == "__main__":
    # Test different providers
    print("=== Testing OpenAI ===")
    asyncio.run(test_openai())

    print("\n=== Testing Anthropic ===")
    asyncio.run(test_anthropic())

    print("\n=== Testing Ollama ===")
    # asyncio.run(test_ollama())  # Uncomment if Ollama is running

    print("\n=== Testing Streaming ===")
    asyncio.run(test_streaming())
