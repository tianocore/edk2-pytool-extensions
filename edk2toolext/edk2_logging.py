# @file edk2_logging.py
# Handle basic logging config for builds;
# splits logs into a master log and per package.
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import logging
import os
import shutil
import re

try:
    from edk2toollib.log import ansi_handler
except ImportError:
    ansi_handler = None
try:
    from edk2toollib.log import markdown_handler
except ImportError:
    markdown_handler = None
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
def clean_build_logs(ws, sub_directory=None):
    # Make sure that we have a clean environment.
    if sub_directory is None:
        sub_directory = os.path.join("Build", "BuildLogs")
    if os.path.isdir(os.path.join(ws, sub_directory)):
        shutil.rmtree(os.path.join(ws, sub_directory))


def get_section_level():
    return SECTION


def get_subsection_level():
    return SUB_SECTION


def get_progress_level():
    return PROGRESS


def get_edk2_filter(verbose=False):
    gEdk2Filter = Edk2LogFilter()
    if verbose:
        gEdk2Filter.setVerbose(verbose)
    return gEdk2Filter


def log_progress(message):
    logging.log(get_progress_level(), message)


def setup_section_level():
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
def setup_txt_logger(directory, filename="log", logging_level=logging.INFO,
                     formatter=None, logging_namespace='', isVerbose=False):
    logger = logging.getLogger(logging_namespace)
    log_formatter = formatter
    if log_formatter is None:
        log_formatter = logging.Formatter("%(levelname)s - %(message)s")

    if not os.path.isdir(directory):
        os.makedirs(directory)

    # Create file logger
    logfile_path = os.path.join(directory, filename + ".txt")
    filelogger = file_handler.FileHandler(filename=(logfile_path), mode='w+')
    filelogger.setLevel(logging_level)
    filelogger.setFormatter(log_formatter)
    logger.addHandler(filelogger)

    filelogger.addFilter(get_edk2_filter(isVerbose))

    return logfile_path, filelogger


# creates the markdown logger
def setup_markdown_logger(directory, filename="log", logging_level=logging.INFO,
                          formatter=None, logging_namespace='', isVerbose=False):

    logger = logging.getLogger(logging_namespace)
    log_formatter = formatter
    if log_formatter is None:
        log_formatter = logging.Formatter("%(levelname)s - %(message)s")

    if not os.path.isdir(directory):
        os.makedirs(directory)

    # add markdown handler
    markdown_filename = filename + ".md"
    markdown_path = os.path.join(directory, markdown_filename)
    if markdown_handler:
        markdownHandler = markdown_handler.MarkdownFileHandler(markdown_path, mode="w+")
    else:
        markdownHandler = logging.FileHandler(markdown_path, mode="w+")
    markdownHandler.setFormatter(log_formatter)

    if logging_level <= logging.DEBUG:
        logging_level = logging.INFO  # we don't show debugging output in markdown since it gets too full

    markdownHandler.addFilter(get_edk2_filter(isVerbose))

    markdownHandler.setLevel(logging_level)
    logger.addHandler(markdownHandler)

    return markdown_path, markdownHandler


# sets up a colored console logger
def setup_console_logging(logging_level=logging.INFO, formatter=None, logging_namespace='',
                          isVerbose=False, use_azure_colors=False, use_color=True):

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


def stop_logging(loghandle, logging_namespace=''):
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


def create_output_stream(level=logging.INFO, logging_namespace=''):
    # creates an output stream that is in memory
    if string_handler:
        handler = string_handler.StringStreamHandler()
    else:
        handler = logging.StreamHandler()
    logger = logging.getLogger(logging_namespace)
    handler.setLevel(level)
    logger.addHandler(handler)
    return handler


def remove_output_stream(handler, logging_namespace=''):
    logger = logging.getLogger(logging_namespace)
    if isinstance(handler, list):
        for single_handler in handler:
            logger.removeHandler(single_handler)
    else:
        logger.removeHandler(handler)


def scan_compiler_output(output_stream):
    # seek to the start of the output stream
    def output_compiler_error(match, line, start_txt="Compiler"):
        start, end = match.span()
        source = line[:start]
        error = line[end:]
        num = match.group(1)
        return f"{start_txt} #{num} from {source} {error}"
    problems = []
    output_stream.seek(0, 0)
    error_exp = re.compile(r"error [A-EG-Z]?(\d+):")
    edk2_error_exp = re.compile(r"error F(\d+):")
    build_py_error_exp = re.compile(r"error (\d+)E:")
    linker_error_exp = re.compile(r"error LNK(\d+):")
    warning_exp = re.compile(r"warning [A-Z]?(\d+):")
    for raw_line in output_stream.readlines():
        line = raw_line.strip("\n").strip()
        match = error_exp.search(line)
        if match is not None:
            error = output_compiler_error(match, line, "Compiler")
            problems.append((logging.ERROR, error))
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
    return problems


class Edk2LogFilter(logging.Filter):
    _allowedLoggers = ["root"]

    def __init__(self):
        logging.Filter.__init__(self)
        self._verbose = False
        self._currentSection = "root"

    def setVerbose(self, isVerbose=True):
        self._verbose = isVerbose

    def addSection(self, section):
        # TODO request the global singleton?
        # how to make this class static
        Edk2LogFilter._allowedLoggers.append(section)

    def filter(self, record):
        # check to make sure we haven't already filtered this record
        if record.name not in Edk2LogFilter._allowedLoggers and record.levelno < logging.WARNING and not self._verbose:
            return False

        return True
