import binaryninja

from .config import DEFAULT_LOG_LEVEL, LOG_PREFIX


def rs_debug(s: str):
    logger.log_info(s)


def rs_info(s: str):
    logger.log_info(s)


def rs_warn(s: str):
    logger.log_warn(s)


def rs_error(s: str):
    logger.log_error(s)


def rs_alert(s: str):
    logger.log_alert(s)


def rs_log(s: str, lvl: binaryninja.log.LogLevel = DEFAULT_LOG_LEVEL):
    match lvl:
        case binaryninja.log.LogLevel.DebugLog:
            rs_debug(s)
        case binaryninja.log.LogLevel.WarningLog:
            rs_warn(s)
        case binaryninja.log.LogLevel.ErrorLog:
            rs_error(s)
        case binaryninja.log.LogLevel.AlertLog:
            rs_alert(s)
        case _:
            rs_info(s)


logger = binaryninja.log.Logger(0, LOG_PREFIX)
