"""Tạo LLM client từ cấu hình. Thêm loại server mới: thêm vào PROVIDERS (nếu tương thích OpenAI) hoặc viết class mới
theo interface BaseLLMClient rồi đăng ký ở đây."""
from agent.llm.base import BaseLLMClient
from agent.llm.client import LLMClient

# provider -> URL mặc định (tất cả dùng API tương thích OpenAI)
PROVIDERS = {
    "ollama": "http://localhost:11434/v1",
    "vllm": "http://localhost:8000/v1"
}


def create_llm_client(
    provider: str,
    model: str,
    base_url: str = "",
    api_key: str = "",
    timeout: float = 90.0,
    temperature: float = 0.2,
    max_tokens: int = 600,
    response_format: str = "json_schema",
    extra_body: dict | None = None,
) -> BaseLLMClient | None:
    """Trả về None nếu provider = none (agent chỉ dùng mẫu văn bản)."""
    provider = provider.strip().lower()
    if provider in ("", "none"):
        return None
    if provider not in PROVIDERS:
        raise ValueError(f"Unknown LLM_PROVIDER '{provider}', expected one of {sorted(PROVIDERS)} or 'none'")
    url = base_url or PROVIDERS[provider]
    if not url:
        raise ValueError(f"LLM_BASE_URL is required for provider '{provider}'")
    return LLMClient(url, model, api_key=api_key, timeout=timeout, temperature=temperature,
                     max_tokens=max_tokens, response_format=response_format, extra_body=extra_body)
