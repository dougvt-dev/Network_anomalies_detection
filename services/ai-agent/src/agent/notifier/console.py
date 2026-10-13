import logging

from agent.notifier.formatting import proposal_text
from agent.schema import Proposal

logger = logging.getLogger("agent.notifications")


class ConsoleNotifier:
    """Dùng khi chưa cấu hình Telegram: in thông báo ra log, duyệt qua API."""

    async def send_proposal(self, proposal: Proposal) -> dict | None:
        logger.info("NEW PROPOSAL\n" + proposal_text(proposal))
        return None

    async def update_proposal(self, proposal: Proposal) -> None:
        logger.info(f"Proposal {proposal.proposal_id} -> {proposal.status}")

    async def send_text(self, text: str) -> None:
        logger.info(text)
