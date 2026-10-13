"""Telegram bot: gửi đề xuất có nút Approve/Reject, nhận lệnh /report /pending /status.

- Long polling (getUpdates): không cần mở cổng vào máy chạy agent.
- Chỉ user ID trong TELEGRAM_ADMIN_IDS được bấm nút hoặc ra lệnh.
- Gửi văn bản thuần (không parse_mode) để dữ liệu từ traffic không chèn được định dạng.
"""
import asyncio
import logging
from typing import Protocol

import httpx

from agent.notifier.formatting import proposal_text
from agent.schema import Proposal

logger = logging.getLogger(__name__)


class TelegramError(Exception):
    pass


class CommandHandler(Protocol):
    async def handle_command(self, user: str, text: str) -> str: ...
    async def handle_callback(self, user: str, data: str) -> str: ...


class TelegramNotifier:

    def __init__(self, token: str, chat_id: str, admin_ids: list[str], http: httpx.AsyncClient | None = None,
                 api_base: str = "https://api.telegram.org", poll_timeout: int = 30):
        self.chat_id = chat_id
        self.admin_ids = {str(a) for a in admin_ids}
        self.poll_timeout = poll_timeout
        self._url = f"{api_base}/bot{token}"
        self._http = http or httpx.AsyncClient(timeout=poll_timeout + 10)
        self._offset = 0

    async def _call(self, method: str, **params) -> dict:
        try:
            response = await self._http.post(f"{self._url}/{method}", json=params)
            data = response.json()
        except (httpx.HTTPError, ValueError) as e:
            raise TelegramError(f"{method} failed: {type(e).__name__}") from e   # không log URL (chứa token)
        if not data.get("ok"):
            raise TelegramError(f"{method} failed: {data.get('description')}")
        return data["result"]

    @staticmethod
    def _keyboard(p: Proposal) -> dict | None:
        if p.status != "pending":
            return None
        return {"inline_keyboard": [[
            {"text": "✅ Approve", "callback_data": f"approve:{p.proposal_id}"},
            {"text": "❌ Reject", "callback_data": f"reject:{p.proposal_id}"},
        ]]}

    async def send_proposal(self, proposal: Proposal) -> dict | None:
        params = {"chat_id": self.chat_id, "text": proposal_text(proposal)}
        keyboard = self._keyboard(proposal)
        if keyboard:
            params["reply_markup"] = keyboard
        result = await self._call("sendMessage", **params)
        return {"chat_id": result["chat"]["id"], "message_id": result["message_id"]}

    async def update_proposal(self, proposal: Proposal) -> None:
        ref = proposal.notification_ref
        if not ref:
            return
        params = {"chat_id": ref["chat_id"], "message_id": ref["message_id"], "text": proposal_text(proposal)}
        keyboard = self._keyboard(proposal)
        params["reply_markup"] = keyboard or {"inline_keyboard": []}       # bỏ nút khi không còn chờ duyệt
        try:
            await self._call("editMessageText", **params)
        except TelegramError as e:
            if "message is not modified" not in str(e):
                raise

    async def send_text(self, text: str, chat_id: str | int | None = None) -> None:
        await self._call("sendMessage", chat_id=chat_id or self.chat_id, text=text[:4000])

    def is_admin(self, user_id) -> bool:
        return str(user_id) in self.admin_ids

    async def poll_once(self, handler: CommandHandler) -> int:
        updates = await self._call("getUpdates", offset=self._offset, timeout=self.poll_timeout,
                                   allowed_updates=["message", "callback_query"])
        for update in updates:
            self._offset = max(self._offset, update["update_id"] + 1)
            try:
                await self._dispatch(update, handler)
            except TelegramError as e:
                logger.warning(f"Telegram reply failed: {e}")
        return len(updates)

    async def run_polling(self, handler: CommandHandler) -> None:
        while True:
            try:
                await self.poll_once(handler)
            except TelegramError as e:
                logger.warning(f"Telegram polling error: {e}")
                await asyncio.sleep(5)

    async def _dispatch(self, update: dict, handler: CommandHandler) -> None:
        if "callback_query" in update:
            query = update["callback_query"]
            user = query.get("from", {})
            if not self.is_admin(user.get("id")):
                logger.warning(f"Unauthorized approval attempt from Telegram user {user.get('id')}")
                await self._call("answerCallbackQuery", callback_query_id=query["id"],
                                 text="You are not authorized to approve actions.", show_alert=True)
                return
            reply = await handler.handle_callback(_user_label(user), query.get("data", ""))
            await self._call("answerCallbackQuery", callback_query_id=query["id"], text=reply[:190])
            return

        message = update.get("message") or {}
        text = (message.get("text") or "").strip()
        if not text.startswith("/"):
            return
        user = message.get("from", {})
        chat_id = message.get("chat", {}).get("id")
        if not self.is_admin(user.get("id")):
            logger.warning(f"Unauthorized command from Telegram user {user.get('id')}")
            await self.send_text("You are not authorized to use this bot.", chat_id=chat_id)
            return
        reply = await handler.handle_command(_user_label(user), text)
        await self.send_text(reply, chat_id=chat_id)


def _user_label(user: dict) -> str:
    name = user.get("username") or user.get("first_name") or "user"
    return f"telegram:{name}({user.get('id')})"
