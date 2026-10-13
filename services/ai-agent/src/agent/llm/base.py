from typing import Protocol


class LLMError(Exception):
    """LLM lỗi, quá thời gian, hoặc trả về nội dung không đọc được."""


class BaseLLMClient(Protocol):
    """Interface duy nhất mà phần còn lại của agent dùng để gọi LLM.

    Thay server (Ollama → vLLM → ...) = thay implementation / cấu hình, không sửa code nghiệp vụ.
    """

    model: str

    async def generate_json(self, system: str, user: str, schema: dict, schema_name: str = "output") -> dict:
        """Sinh một object JSON theo `schema` (JSON Schema). Raise LLMError nếu thất bại."""
        ...

    async def aclose(self) -> None:
        ...
