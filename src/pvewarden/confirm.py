"""Ask the human, not the agent, before destructive actions.

Uses MCP elicitation: the client shows the question to the user and only the user's answer comes back.
The agent cannot answer it, so "roll back CT102" from a confused or prompt-injected agent still needs a
person to click. Two protocol eras are handled:

- handshake protocols (up to 2025-11-25): the server sends an elicitation/create request mid-call;
- 2026-07-28: the tool returns InputRequiredResult and the client retries the call with the answer.
"""

from mcp.server.elicitation import render_elicitation_schema
from mcp.server.mcpserver import Context
from mcp.shared.exceptions import NoBackChannelError
from mcp_types import ElicitRequest, ElicitRequestFormParams, ElicitResult, InputRequiredResult
from mcp_types.version import MODERN_PROTOCOL_VERSIONS
from pydantic import BaseModel, Field

from pvewarden.errors import PolicyError

KEY = "confirm"


class Confirmation(BaseModel):
    confirm: bool = Field(default=False, title="Yes, do it", description="Tick to confirm")


def _accepted(result: ElicitResult) -> bool:
    return result.action == "accept" and bool((result.content or {}).get("confirm"))


def _declined() -> PolicyError:
    return PolicyError("the user did not confirm this action; nothing was changed")


def _unsupported() -> PolicyError:
    return PolicyError(
        "this action needs the user's confirmation, but this MCP client cannot ask the user (no elicitation "
        "support); nothing was changed. The user can do it in the Proxmox UI, use a client that supports "
        'elicitation, or set [policy] confirm_destructive = "if-supported" on the pvewarden server'
    )


async def confirm(ctx: Context, mode: str, message: str, state: str) -> InputRequiredResult | None:
    """Ask the user. Returns None to go ahead, or an InputRequiredResult the tool must return as is.

    `state` identifies the action (e.g. "rollback:102:pvewarden_..."): on 2026-07-28 the answer only
    counts for a retry of the very same action. Raises PolicyError when declined or impossible.
    """
    if mode == "off":
        return None
    caps = ctx.client_capabilities
    if caps is None or caps.elicitation is None:
        if mode == "if-supported":
            return None
        raise _unsupported()

    if ctx.protocol_version in MODERN_PROTOCOL_VERSIONS:
        answer = (ctx.input_responses or {}).get(KEY)
        if answer is not None and ctx.request_state == state:
            if isinstance(answer, ElicitResult) and _accepted(answer):
                return None
            raise _declined()
        return InputRequiredResult(
            input_requests={
                KEY: ElicitRequest(
                    params=ElicitRequestFormParams(
                        message=message, requested_schema=render_elicitation_schema(Confirmation)
                    )
                )
            },
            request_state=state,
        )

    try:
        result = await ctx.elicit(message, Confirmation)
    except NoBackChannelError:
        if mode == "if-supported":
            return None
        raise _unsupported() from None
    if result.action == "accept" and result.data.confirm:
        return None
    raise _declined()
