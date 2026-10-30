"""Expected errors. Their messages are shown to the agent; anything else is reported as a crash."""


class WardenError(Exception):
    pass


class PolicyError(WardenError):
    """The guest's tags (or a pvewarden rule) do not allow the operation."""


class NotFoundError(WardenError):
    pass


class InvalidRequestError(WardenError):
    pass


class ProxmoxError(WardenError):
    pass


class GuestError(WardenError):
    pass
