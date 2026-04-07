from util.consts import LOGGING_PATH
import logging


class AuthenticationFilter(logging.Filter):
    def filter(self, record):
        if 'password' in record.msg.lower():
            return False
        return True


def init_logger(level: str, filename: str = "bluecat_adapter.log") -> logging.Logger:
    """
    This function initializes the logger for the Bluecat Adapter. It creates a handler and formatter as well as
    adding an authentication filter to the logger. It then suppresses the urllib3 logger so any auths are not recorded
    by the root logger that that library uses.

    :param level: The level of logs to record.
    :param filename: The name of the log file.
    :return: The configured logger.
    """
    if level not in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
        raise ValueError(f"Invalid log level of {level}")

    logger_name = "BCA"
    logger = logging.Logger(logger_name, level=level.upper())

    if filename[-4:] != ".log":
        filename += ".log"
    log_filename = LOGGING_PATH.joinpath(filename)

    formatter = logging.Formatter('%(name)s: %(asctime)s - %(levelname)s - %(message)s')
    file_handler = logging.FileHandler(filename=log_filename)
    file_handler.setFormatter(formatter)

    if logger.hasHandlers():
        logger.handlers.clear()
    logger.addHandler(file_handler)

    logger.addFilter(AuthenticationFilter())

    logging.getLogger("urllib3").setLevel(logging.WARNING)

    return logger
