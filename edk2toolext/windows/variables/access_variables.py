import argparse
import ctypes
import logging
import os
import sys

import tomllib

# Some of these libraries are windows only, so we need to import them conditionally
if sys.platform == "win32":
    import pywintypes
    import win32api
    import win32process
    import win32security

if sys.platform == "win32":
    KERNEL32 = ctypes.windll.kernel32
    EFI_VAR_MAX_BUFFER_SIZE = 1024 * 1024

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
VAR_DEBUG_DIR = os.path.join(ROOT_DIR, "VAR_DEBUG")

###################################################################################################
# Classes
###################################################################################################


class FirmwareVariables(object):
    """Class to interact with firmware variables."""

    def __init__(self) -> None:
        """Constructor."""
        # enable required SeSystemEnvironmentPrivilege privilege
        privilege = win32security.LookupPrivilegeValue(
            None, "SeSystemEnvironmentPrivilege"
        )

        token = win32security.OpenProcessToken(
            win32process.GetCurrentProcess(),
            win32security.TOKEN_READ | win32security.TOKEN_ADJUST_PRIVILEGES,
        )

        win32security.AdjustTokenPrivileges(
            token, False, [(privilege, win32security.SE_PRIVILEGE_ENABLED)]
        )

        win32api.CloseHandle(token)

        try:
            self._GetFirmwareEnvironmentVariable = (
                KERNEL32.GetFirmwareEnvironmentVariableW
            )
            self._GetFirmwareEnvironmentVariable.restype = ctypes.c_int
            self._GetFirmwareEnvironmentVariable.argtypes = [
                ctypes.c_wchar_p,
                ctypes.c_wchar_p,
                ctypes.c_void_p,
                ctypes.c_int,
            ]
        except AttributeError:
            self._GetFirmwareEnvironmentVariable = None
            logging.warning("Get function doesn't exist")

    def get_variable(self, name: str, guid: str) -> bytes:
        """Gets a firmware variable.

        Args:
            name (str): Name of the variable to get
            guid (str): GUID of the variable to get

        Returns:
          The value of the variable
        """
        if self._GetFirmwareEnvironmentVariable is None:
            raise NotImplementedError(
                "GetFirmwareEnvironmentVariable is not implemented"
            )

        buffer = ctypes.create_string_buffer(EFI_VAR_MAX_BUFFER_SIZE)
        buffer_size = ctypes.c_int(EFI_VAR_MAX_BUFFER_SIZE)
        result = self._GetFirmwareEnvironmentVariable(name, guid, buffer, buffer_size)
        if result == 0:
            last_error = win32api.GetLastError()

            raise pywintypes.error(
                last_error,
                "GetFirmwareEnvironmentVariable",
                win32api.FormatMessage(last_error),
            )

        return buffer.raw[:result]

def main():

    parser = argparse.ArgumentParser(description="Access UEFI Variables")

    # Read an Ini configuration file
    parser.add_argument(
        "-c",
        "--config",
        help="config to read",
        required=True,
    )

    args = parser.parse_args()

    # remove existing folder and create a new one
    if os.path.exists(VAR_DEBUG_DIR):
        import shutil

        shutil.rmtree(VAR_DEBUG_DIR)

    os.makedirs(VAR_DEBUG_DIR, exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(os.path.join(VAR_DEBUG_DIR, "Variables_Debug.log")),
            logging.StreamHandler()
        ]
    )

    with open(args.config, "rb") as f:
        config = tomllib.load(f)

    for section in config.keys():
        logging.info(f"Parsing [{section}]")

        for key in config[section]:
            if key == "variables":
                logging.info(f"Getting variables for {section}")

                for var in config[section][key]:
                    try:
                        firmware = FirmwareVariables()
                        logging.info(f"Getting variable {var['name']} from {var['namespace']}")
                        value = firmware.get_variable(var["name"], var["namespace"])

                        with open(os.path.join(VAR_DEBUG_DIR, f"{var['name']}.bin"), "wb") as f:
                            f.write(value)
                        logging.info(f"Saved: {os.path.join(VAR_DEBUG_DIR, f"{var['name']}.bin")}")
                    except Exception as e:
                        logging.error(f"Error: {e}")

if __name__ == "__main__":

    main()
