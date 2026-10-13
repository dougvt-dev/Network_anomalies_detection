"""LLMClient: gọi mọi server có API tương thích OpenAI (/v1/chat/completions) — Ollama, vLLM, LM Studio, ...

Tham số riêng của từng server (vd tắt chế độ thinking) truyền qua `extra_body`, không cần sửa code:
- Ollama:            {"reasoning_effort": "none"}
- vLLM (Qwen3/3.5):  {"chat_template_kwargs": {"enable_thinking": false}}
"""
import json
import logging

import httpx

from agent.llm.base import LLMError

logger = logging.getLogger(__name__)


class LLMClient:

    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str = "",
        timeout: float = 90.0,
        temperature: float = 0.2,
        max_tokens: int = 600,
        response_format: str = "json_schema",   # json_schema | json_object | none
        extra_body: dict | None = None,         # tham số riêng của server, gộp vào request
        http: httpx.AsyncClient | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.response_format = response_format
        self.extra_body = extra_body or {}
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self._http = http or httpx.AsyncClient(timeout=timeout, headers=headers)

    async def generate_json(self, system: str, user: str, schema: dict, schema_name: str = "output") -> dict:
        body = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            **self.extra_body,
        }
        if self.response_format == "json_schema":
            # Server ép output đúng schema (Ollama >= 0.5, vLLM)
            body["response_format"] = {"type": "json_schema",
                                       "json_schema": {"name": schema_name, "strict": True, "schema": schema}}
        else:
            if self.response_format == "json_object":
                body["response_format"] = {"type": "json_object"}
            body["messages"][0]["content"] = (
                f"{system}\n\nRespond with a single JSON object matching this JSON Schema:\n{json.dumps(schema)}"
            )

        try:
            response = await self._http.post(f"{self.base_url}/chat/completions", json=body)
            response.raise_for_status()
            choice = response.json()["choices"][0]
            content = choice["message"]["content"]
        except (httpx.HTTPError, KeyError, IndexError, ValueError) as e:
            raise LLMError(f"LLM request failed: {type(e).__name__}: {e}") from e

        if not content and choice.get("finish_reason") == "length":
            # Model dùng hết max_tokens cho phần suy nghĩ (thinking) mà chưa trả lời
            raise LLMError("LLM returned no content (max_tokens reached; disable thinking via LLM_EXTRA_BODY?)")
        return _parse_json_object(content)

    async def aclose(self) -> None:
        await self._http.aclose()


def _parse_json_object(content: str) -> dict:
    text = (content or "").strip()
    if text.startswith("```"):                     # một số model bọc JSON trong ```json ... ```
        text = text.strip("`")
        text = text[text.find("{"):] if "{" in text else text
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        raise LLMError(f"LLM response is not JSON: {content[:200]!r}")
    try:
        value = json.loads(text[start:end + 1])
    except ValueError as e:
        raise LLMError(f"LLM response is not valid JSON: {e}") from e
    if not isinstance(value, dict):
        raise LLMError("LLM response is not a JSON object")
    return value
