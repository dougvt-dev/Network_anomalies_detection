import asyncio
import json

import httpx
import pytest

from agent.llm import PROVIDERS, LLMClient, LLMError, create_llm_client

SCHEMA = {"type": "object", "properties": {"x": {"type": "string"}}, "required": ["x"]}


def client_with(handler, **kwargs) -> tuple[LLMClient, list]:
    requests = []

    def record(request: httpx.Request):
        requests.append(request)
        return handler(request)

    http = httpx.AsyncClient(transport=httpx.MockTransport(record))
    return LLMClient("http://llm.local/v1", "test-model", http=http, **kwargs), requests


def chat_response(content: str) -> httpx.Response:
    return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})


def test_json_schema_request_and_parse():
    client, requests = client_with(lambda r: chat_response('{"x": "hello"}'))
    assert asyncio.run(client.generate_json("sys", "user", SCHEMA, "thing")) == {"x": "hello"}

    body = json.loads(requests[0].content)
    assert str(requests[0].url) == "http://llm.local/v1/chat/completions"
    assert body["model"] == "test-model"
    assert body["messages"][0] == {"role": "system", "content": "sys"}
    assert body["response_format"]["type"] == "json_schema"
    assert body["response_format"]["json_schema"]["schema"] == SCHEMA


def test_json_object_mode_puts_schema_in_prompt():
    client, requests = client_with(lambda r: chat_response('```json\n{"x": "fenced"}\n```'), response_format="json_object")
    assert asyncio.run(client.generate_json("sys", "user", SCHEMA)) == {"x": "fenced"}
    body = json.loads(requests[0].content)
    assert body["response_format"] == {"type": "json_object"} and "JSON Schema" in body["messages"][0]["content"]


@pytest.mark.parametrize("response", [
    httpx.Response(500, text="boom"),
    chat_response("not json at all"),
    chat_response("[1, 2]"),
    httpx.Response(200, json={"unexpected": True}),
])
def test_errors_raise_llm_error(response):
    client, _ = client_with(lambda r: response)
    with pytest.raises(LLMError):
        asyncio.run(client.generate_json("sys", "user", SCHEMA))


def test_extra_body_is_merged():
    client, requests = client_with(lambda r: chat_response('{"x": "y"}'),
                                   extra_body={"chat_template_kwargs": {"enable_thinking": False}})
    asyncio.run(client.generate_json("sys", "user", SCHEMA))
    assert json.loads(requests[0].content)["chat_template_kwargs"] == {"enable_thinking": False}


def test_thinking_exhausted_tokens_gives_clear_error():
    def handler(request):
        return httpx.Response(200, json={"choices": [{"message": {"content": "", "reasoning": "Thinking..."},
                                                      "finish_reason": "length"}]})
    client, _ = client_with(handler)
    with pytest.raises(LLMError, match="LLM_EXTRA_BODY"):
        asyncio.run(client.generate_json("sys", "user", SCHEMA))


def test_factory_providers():
    assert create_llm_client("none", "m") is None
    assert create_llm_client("ollama", "gemma:latest").base_url == PROVIDERS["ollama"]
    vllm = create_llm_client("vllm", "Qwen/Qwen2.5-7B-Instruct-AWQ", base_url="http://gpu-server:8000/v1",
                             extra_body={"chat_template_kwargs": {"enable_thinking": False}})
    assert isinstance(vllm, LLMClient) and vllm.base_url == "http://gpu-server:8000/v1"
    assert vllm.extra_body == {"chat_template_kwargs": {"enable_thinking": False}}
    with pytest.raises(ValueError):
        create_llm_client("openai_compat", "m")          # thiếu base_url
    with pytest.raises(ValueError):
        create_llm_client("unknown", "m")
