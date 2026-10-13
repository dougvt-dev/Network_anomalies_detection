from typing import Protocol

from agent.schema import Proposal


class Notifier(Protocol):
    """Kênh liên lạc với người quản trị. Thêm kênh mới (email, Mattermost...): viết class theo interface này."""

    async def send_proposal(self, proposal: Proposal) -> dict | None:
        """Gửi đề xuất (kèm nút duyệt nếu cần). Trả về tham chiếu tin nhắn để cập nhật sau."""
        ...

    async def update_proposal(self, proposal: Proposal) -> None:
        """Cập nhật tin nhắn đề xuất khi trạng thái đổi (đã duyệt, hết hạn, đã thực thi...)."""
        ...

    async def send_text(self, text: str) -> None:
        ...
