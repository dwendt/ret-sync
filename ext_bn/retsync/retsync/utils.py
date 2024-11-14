from binaryninja import BinaryView
from binaryninjaui import UIContext


def current_binary_view() -> BinaryView | None:
    ctx = UIContext.activeContext()
    if not ctx:
        return None
    action_handler = ctx.contentActionHandler()
    if not action_handler:
        return None
    action_ctx = action_handler.actionContext()
    if not action_ctx:
        return None
    return action_ctx.binaryView
