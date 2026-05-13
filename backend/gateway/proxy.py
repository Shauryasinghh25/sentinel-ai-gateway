"""
gateway/proxy.py — LLM Reverse Proxy & Multi-Model Router

Routes requests to the appropriate LLM provider:
- OpenAI (GPT-4o, GPT-4o-mini, GPT-3.5-turbo)
- Anthropic Claude (claude-3-5-sonnet, claude-3-haiku)
- Google Gemini (gemini-1.5-pro, gemini-1.5-flash)
- Ollama (local models)

Features:
- Automatic failover to fallback model
- Provider health checking
- Token usage tracking
- Response time monitoring
"""
import time
import asyncio
from typing import Optional, Dict, Any, AsyncGenerator
from loguru import logger

from backend.config import settings
from backend.models.schemas import GatewayRequest, LLMProvider, Message


class LLMProviderError(Exception):
    """Raised when an LLM provider call fails."""
    pass


class LLMProxy:
    """
    Multi-provider LLM proxy with automatic routing and failover.
    """

    def __init__(self):
        self._provider_health: Dict[str, bool] = {
            "openai": True,
            "anthropic": True,
            "google": True,
            "ollama": True,
        }

    async def call(
        self,
        request: GatewayRequest,
        input_text: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Route a request to the appropriate LLM provider.

        Args:
            request: Gateway request with model/provider info
            input_text: Optionally overrides the last user message (e.g. sanitized)

        Returns:
            {"content": str, "usage": dict, "model": str, "provider": str, "latency_ms": float}
        """
        messages = request.messages
        if input_text:
            # Replace last user message with sanitized version
            messages = [
                *messages[:-1],
                Message(role="user", content=input_text),
            ]

        t0 = time.perf_counter()

        try:
            result = await self._dispatch(
                provider=request.provider,
                model=request.model,
                messages=messages,
                max_tokens=request.max_tokens,
                temperature=request.temperature,
            )
            result["latency_ms"] = round((time.perf_counter() - t0) * 1000, 2)
            return result

        except LLMProviderError as e:
            logger.warning(f"Primary provider failed ({request.provider}): {e}. Trying fallback.")
            self._provider_health[request.provider.value] = False

            # Attempt fallback
            return await self._fallback(
                request=request,
                messages=messages,
                t0=t0,
            )

    async def _dispatch(
        self,
        provider: LLMProvider,
        model: str,
        messages: list,
        max_tokens: int,
        temperature: float,
    ) -> Dict[str, Any]:
        """Dispatch to the correct provider handler."""
        if provider == LLMProvider.OPENAI:
            return await self._call_openai(model, messages, max_tokens, temperature)
        elif provider == LLMProvider.ANTHROPIC:
            return await self._call_anthropic(model, messages, max_tokens, temperature)
        elif provider == LLMProvider.GOOGLE:
            return await self._call_google(model, messages, max_tokens, temperature)
        elif provider == LLMProvider.OLLAMA:
            return await self._call_ollama(model, messages, max_tokens, temperature)
        else:
            raise LLMProviderError(f"Unknown provider: {provider}")

    async def _call_openai(
        self, model: str, messages: list, max_tokens: int, temperature: float
    ) -> Dict[str, Any]:
        if not settings.OPENAI_API_KEY:
            raise LLMProviderError("OpenAI API key not configured")

        from openai import AsyncOpenAI
        client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)

        try:
            response = await client.chat.completions.create(
                model=model,
                messages=[{"role": m.role, "content": m.content} for m in messages],
                max_tokens=max_tokens,
                temperature=temperature,
            )
            return {
                "content": response.choices[0].message.content,
                "model": response.model,
                "provider": "openai",
                "usage": {
                    "prompt_tokens": response.usage.prompt_tokens,
                    "completion_tokens": response.usage.completion_tokens,
                    "total_tokens": response.usage.total_tokens,
                },
            }
        except Exception as e:
            raise LLMProviderError(f"OpenAI error: {e}")

    async def _call_anthropic(
        self, model: str, messages: list, max_tokens: int, temperature: float
    ) -> Dict[str, Any]:
        if not settings.ANTHROPIC_API_KEY:
            raise LLMProviderError("Anthropic API key not configured")

        import anthropic
        client = anthropic.AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)

        # Separate system message
        system_msg = None
        chat_messages = []
        for m in messages:
            if m.role == "system":
                system_msg = m.content
            else:
                chat_messages.append({"role": m.role, "content": m.content})

        try:
            kwargs = {
                "model": model,
                "max_tokens": max_tokens,
                "temperature": temperature,
                "messages": chat_messages,
            }
            if system_msg:
                kwargs["system"] = system_msg

            response = await client.messages.create(**kwargs)
            return {
                "content": response.content[0].text,
                "model": response.model,
                "provider": "anthropic",
                "usage": {
                    "prompt_tokens": response.usage.input_tokens,
                    "completion_tokens": response.usage.output_tokens,
                    "total_tokens": response.usage.input_tokens + response.usage.output_tokens,
                },
            }
        except Exception as e:
            raise LLMProviderError(f"Anthropic error: {e}")

    async def _call_google(
        self, model: str, messages: list, max_tokens: int, temperature: float
    ) -> Dict[str, Any]:
        if not settings.GOOGLE_API_KEY:
            raise LLMProviderError("Google API key not configured")

        import google.generativeai as genai
        genai.configure(api_key=settings.GOOGLE_API_KEY)

        try:
            gemini_model = genai.GenerativeModel(model)
            # Convert messages to Gemini format
            prompt = "\n".join(f"{m.role}: {m.content}" for m in messages)
            response = await asyncio.to_thread(
                gemini_model.generate_content,
                prompt,
                generation_config=genai.types.GenerationConfig(
                    max_output_tokens=max_tokens,
                    temperature=temperature,
                )
            )
            return {
                "content": response.text,
                "model": model,
                "provider": "google",
                "usage": {"total_tokens": 0},
            }
        except Exception as e:
            raise LLMProviderError(f"Google error: {e}")

    async def _call_ollama(
        self, model: str, messages: list, max_tokens: int, temperature: float
    ) -> Dict[str, Any]:
        import httpx
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(
                    f"{settings.OLLAMA_BASE_URL}/api/chat",
                    json={
                        "model": model,
                        "messages": [{"role": m.role, "content": m.content} for m in messages],
                        "stream": False,
                        "options": {"temperature": temperature, "num_predict": max_tokens},
                    }
                )
                response.raise_for_status()
                data = response.json()
                return {
                    "content": data["message"]["content"],
                    "model": model,
                    "provider": "ollama",
                    "usage": {
                        "prompt_tokens": data.get("prompt_eval_count", 0),
                        "completion_tokens": data.get("eval_count", 0),
                        "total_tokens": data.get("prompt_eval_count", 0) + data.get("eval_count", 0),
                    },
                }
        except Exception as e:
            raise LLMProviderError(f"Ollama error: {e}")

    async def _fallback(
        self,
        request: GatewayRequest,
        messages: list,
        t0: float,
    ) -> Dict[str, Any]:
        """Try fallback model (OpenAI GPT-3.5 by default)."""
        try:
            result = await self._call_openai(
                "gpt-3.5-turbo", messages, request.max_tokens, request.temperature
            )
            result["latency_ms"] = round((time.perf_counter() - t0) * 1000, 2)
            result["fallback"] = True
            return result
        except LLMProviderError as e:
            raise LLMProviderError(f"All providers failed. Last error: {e}")

    def get_provider_health(self) -> Dict[str, bool]:
        return dict(self._provider_health)
