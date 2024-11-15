import binaryninja

from .config import DEFAULT_LOG_LEVEL, LOG_PREFIX


def rs_debug(s: str):
    logger.log_debug(s)


def rs_info(s: str):
    logger.log_info(s)


def rs_warn(s: str):
    logger.log_warn(s)


def rs_error(s: str):
    logger.log_error(s)


def rs_log(s: str, lvl: binaryninja.log.LogLevel = binaryninja.log.LogLevel.InfoLog):
    if lvl < DEFAULT_LOG_LEVEL:
        return

    cb = None

    match lvl:
        case binaryninja.log.LogLevel.DebugLog:
            cb = logger.log_debug
        case binaryninja.log.LogLevel.WarningLog:
            cb = logger.log_warn
        case binaryninja.log.LogLevel.ErrorLog:
            cb = logger.log_error
        case _:
            cb = logger.log_info

    if cb:
        cb(s)


logger = binaryninja.log.Logger(0, LOG_PREFIX)
