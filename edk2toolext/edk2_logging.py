# @file edk2_logging.py
# Handle basic logging config for invocables;
# splits logs into a master log and per package.
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Handles basic logging config for invocables.

edk2_logging will automatically filter logs for PATs / Secrets when it is
detected that the invocable is running on a CI system. It does this via
searching for "CI" or "TF_BUILD" in the os's environment variables. If either
of these exists and and are set to TRUE, filtering will occur.

Splits logs into a master log and per package log.
"""

import logging
import os
import re
import shutil
from typing import Optional, TextIO, Union

try:
    from edk2toollib.log import ansi_handler
except ImportError:
    ansi_handler = None
try:
    from edk2toollib.log import string_handler
except ImportError:
    string_handler = None
try:
    from edk2toollib.log import file_handler
except ImportError:
    file_handler = logging


# These three are for emitting different events
# section is for marking different sections of the build process
# subsection is similar to sub section but denotes a subsection of the current section
# both of the section levels are high enough that they won't get filtered out
# progress is for marking things like a process completed. Similar to critical but doesn't mean the process is exiting
# progress is below critical so it can be turned off but still high enough that it doesn't get filtered out
SECTION = logging.CRITICAL + 2  # just above critical
SUB_SECTION = logging.CRITICAL + 1  # just above critical
PROGRESS = logging.CRITICAL - 1  # just below critical


# sub_directory is relative to ws argument
def clean_build_logs(ws: str, sub_directory: Optional[str] = None) -> None:
    """Removes all build logs."""
    # Make sure that we have a clean environment.
    if sub_directory is None:
        sub_directory = os.path.join("Build", "BuildLogs")
    if os.path.isdir(os.path.join(ws, sub_directory)):
        shutil.rmtree(os.path.join(ws, sub_directory))


def get_section_level() -> int:
    """Returns SECTION."""
    return SECTION


def get_subsection_level() -> int:
    """Returns SUB_SECTION."""
    return SUB_SECTION


def get_progress_level() -> int:
    """Returns PROGRESS."""
    return PROGRESS


def get_edk2_filter(verbose: bool = False) -> logging.Filter:
    """Returns an edk2 filter."""
    gEdk2Filter = Edk2LogFilter()
    if verbose:
        gEdk2Filter.setVerbose(verbose)
    return gEdk2Filter


def log_progress(message: str) -> None:
    """Creates a logging message at the progress section level."""
    logging.log(get_progress_level(), message)


def setup_section_level() -> None:
    """Sets up different sections to log to."""
    # todo define section level
    # add section as a level to the logger
    section_level = get_section_level()
    subsection_level = get_subsection_level()
    progress_level = get_progress_level()
    if logging.getLevelName(section_level) != "SECTION":
        logging.addLevelName(section_level, "SECTION")
    if logging.getLevelName(subsection_level) != "SUBSECTION":
        logging.addLevelName(subsection_level, "SUBSECTION")
    if logging.getLevelName(progress_level) != "PROGRESS":
        logging.addLevelName(progress_level, "PROGRESS")


# creates the the plaintext logger
def setup_txt_logger(
    directory: str,
    filename: str = "log",
    logging_level: int = logging.INFO,
    formatter: Optional[logging.Formatter] = None,
    logging_namespace: Optional[str] = "",
    isVerbose: bool = False,
) -> tuple:
    """Configures a text logger."""
    logger = logging.getLogger(logging_namespace)
    log_formatter = formatter
    if log_formatter is None:
        log_formatter = logging.Formatter("%(levelname)s - %(message)s")

    if not os.path.isdir(directory):
        os.makedirs(directory)

    logfile_path = os.path.join(directory, filename + ".txt")

    # delete file before starting a new log
    if os.path.isfile(logfile_path):
        os.remove(logfile_path)

    # Create file logger
    filelogger = file_handler.FileHandler(filename=(logfile_path), mode="a")
    filelogger.setLevel(logging_level)
    filelogger.setFormatter(log_formatter)
    logger.addHandler(filelogger)

    filelogger.addFilter(get_edk2_filter(isVerbose))

    return logfile_path, filelogger


# sets up a colored console logger
def setup_console_logging(
    logging_level: int = logging.INFO,
    formatter: Optional[logging.Formatter] = None,
    logging_namespace: Optional[str] = "",
    isVerbose: bool = False,
    use_azure_colors: bool = False,
    use_color: bool = True,
) -> logging.Handler:
    """Configures a console logger.

    Filtering of secrets will automatically occur if "CI" or "TF_BUILD" is set to TRUE
    in the os's environment.
    """
    if formatter is None and isVerbose:
        formatter_msg = "%(name)s: %(levelname)s - %(message)s"
    elif formatter is None:
        formatter_msg = "%(levelname)s - %(message)s"
    else:
        formatter_msg = formatter

    formatter = logging.Formatter(formatter_msg)

    # create a safe handler so that any logging emitted when creating the ansi logger is handled
    safeHandler = logging.StreamHandler()
    safeHandler.setLevel(logging_level)
    safeHandler.addFilter(get_edk2_filter(isVerbose))
    safeHandler.setFormatter(formatter)
    logger = logging.getLogger(logging_namespace)
    logger.addHandler(safeHandler)

    # create the ansi logger if needed
    if use_azure_colors or use_color and ansi_handler:
        formatter = ansi_handler.ColoredFormatter(formatter_msg, use_azure=use_azure_colors)
        coloredHandler = ansi_handler.ColoredStreamHandler()
        coloredHandler.setLevel(logging_level)
        coloredHandler.addFilter(get_edk2_filter(isVerbose))
        coloredHandler.setFormatter(formatter)
        # make sure to remove the safe handler so we don't have two handlers
        logger.removeHandler(safeHandler)
        logger.addHandler(coloredHandler)
        return coloredHandler
    # return the safe handler if we didn't create a colored handler
    return safeHandler


def stop_logging(
    loghandle: Union[list[logging.Handler], logging.Handler], logging_namespace: Optional[str] = ""
) -> None:
    """Stops logging on a log handle."""
    logger = logging.getLogger(logging_namespace)
    if loghandle is None:
        return
    if isinstance(loghandle, list):
        # if it's an array, process each element as a handle
        for handle in loghandle:
            handle.close()
            logger.removeHandler(handle)
    else:
        loghandle.close()
        logger.removeHandler(loghandle)


def create_output_stream(level: int = logging.INFO, logging_namespace: Optional[str] = "") -> logging.Handler:
    """Creates an output stream to log to."""
    # creates an output stream that is in memory
    if string_handler:
        handler = string_handler.StringStreamHandler()
    else:
        handler = logging.StreamHandler()
    logger = logging.getLogger(logging_namespace)
    handler.setLevel(level)
    logger.addHandler(handler)
    return handler


def remove_output_stream(handler: logging.Handler, logging_namespace: Optional[str] = "") -> None:
    """Removes an output stream to log to."""
    logger = logging.getLogger(logging_namespace)
    if isinstance(handler, list):
        for single_handler in handler:
            logger.removeHandler(single_handler)
    else:
        logger.removeHandler(handler)


def scan_compiler_output(output_stream: TextIO) -> list[tuple]:
    """Scans the compiler for errors and warnings.

    Returns:
        (list[tuple[logging.Type, str]]): list of tuples containing the type
            of issue (Error, warning) and the description.
    """

    # seek to the start of the output stream
    def output_compiler_error(match: re.Match, line: str, start_txt: str = "Compiler") -> str:
        start, end = match.span()
        source = line[:start].strip()
        error = line[end:].strip()
        num = match.group(1)
        return f"{start_txt} #{num} from {source} {error}"

    problems = []
    output_stream.seek(0, 0)
    error_exp = re.compile(r"error [A-EG-Z]?(\d+):")
    # Would prefer to do something like r"(?:\/[^\/: ]*)+\/?:\d+:\d+: (error):"
    # but the script is currently setup on fixed formatting assumptions rather
    # than offering per rule flexibility to parse tokens via regex
    gcc_error_exp = re.compile(r":\d+:\d+: (error):", re.IGNORECASE)
    gcc_fatal_error_exp = re.compile(r"fatal error:")
    edk2_error_exp = re.compile(r"error F(\d+):")
    build_py_error_exp = re.compile(r"error (\d+)E:")
    linker_error_exp = re.compile(r"error LNK(\d+):")
    warning_exp = re.compile(r"warning [A-Z]?(\d+):")
    rust_error_exp = re.compile(r"^(-->|error(?:\[[A-Za-z]\d+\])?:)")
    for raw_line in output_stream.readlines():
        line = raw_line.strip("\n").strip()
        match = error_exp.search(line)
        if match is not None:
            error = output_compiler_error(match, line, "Compiler")
            problems.append((logging.ERROR, error))
        match = gcc_error_exp.search(line)
        if match is not None:
            error = output_compiler_error(match, line, "Compiler")
            problems.append((logging.ERROR, error))
        match = gcc_fatal_error_exp.search(line)
        if match is not None:
            problems.append((logging.ERROR, line))
        match = warning_exp.search(line)
        if match is not None:
            error = output_compiler_error(match, line, "Compiler")
            problems.append((logging.WARNING, error))
        match = linker_error_exp.search(line)
        if match is not None:
            error = output_compiler_error(match, line, "Linker")
            problems.append((logging.ERROR, error))
        match = edk2_error_exp.search(line)
        if match is not None:
            error = output_compiler_error(match, line, "EDK2")
            problems.append((logging.ERROR, error))
        match = build_py_error_exp.search(line)
        if match is not None:
            error = output_compiler_error(match, line, "Build.py")
            problems.append((logging.ERROR, error))
        match = rust_error_exp.search(line)
        if match is not None:
            problems.append((logging.ERROR, line))
    return problems


def setup_performance_logger(enabled: bool, directory: str, file: str) -> None:
    """Sets up a performance logger."""
    if not enabled:
        logging.getLogger("performance").disabled = True
        return

    logfile, filelogger = setup_txt_logger(directory, file, logging.DEBUG, logging_namespace="performance")
    logging.getLogger("performance").propagate = False


def perf_measurement(task: str, time: float) -> None:
    """Logs a performance measurement."""
    logging.getLogger("performance").info(f"{task} took {time:.3f} s")


class Edk2LogFilter(logging.Filter):
    """Subclass of logging.Filter."""

    _allowedLoggers = ["root", "performance", "git.cmd", "edk2toolext.environment.repo_resolver"]

    def __init__(self) -> None:
        """Inits a filter."""
        logging.Filter.__init__(self)
        self._verbose = False
        self._currentSection = "root"
        self.apply_filter = False

        # Turn on filtering for azure pipelines / github actions
        if os.environ.get("CI", "FALSE").upper() == "TRUE" or os.environ.get("TF_BUILD", "FALSE").upper() == "TRUE":
            self.apply_filter = True

        secrets_regex_strings = [
            r"[a-z0-9]{46}",  # Nuget API Key is generated as all lowercase
            r"gh[pousr]_[A-Za-z0-9_]+",  # Github PAT
            r"[a-z0-9]{52}",  # Azure PAT is generated as all lowercase
        ]

        self.secrets_regex = re.compile(r"{}".format("|".join(secrets_regex_strings)), re.IGNORECASE)

    def setVerbose(self, isVerbose: bool = True) -> None:
        """Sets the filter verbosity."""
        self._verbose = isVerbose

    def addSection(self, section: str) -> None:
        """Adds a section to the filter."""
        # TODO request the global singleton?
        # how to make this class static
        Edk2LogFilter._allowedLoggers.append(section)

    def filter(self, record: logging.LogRecord) -> bool:
        """Adds a filter for a record if it doesn't already exist."""
        # check to make sure we haven't already filtered this record
        if record.name not in Edk2LogFilter._allowedLoggers and record.levelno < logging.WARNING and not self._verbose:
            return False
        if self.apply_filter:
            record.msg = self.secrets_regex.sub("*******", str(record.msg))
        return True
