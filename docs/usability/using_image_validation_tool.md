# PE/COFF Image Validation

The PE/COFF image validation tool is a command line tool used to verify that
memory protection requirements such as section alignment and write / execute
settings are applied correctly. This tool also provides the ability to check,
set, and clear the NX_COMPAT flag found in OPTIONAL_HEADER.DllCharacteristics.

## Synopsis

image_validation.py [-h] -i FILE [-d] [-p PROFILE] [--set-nx-compat] [--clear-nx-compat] [--get-nx-compat]

## Options

### -h, --help

    [Optional] Provides information on flags

### -i, --file

    [Required] The input PE/COFF file to be verified

### -p, --profile

    [Optional] The profile config to be verified against. Will use the default, if not provided

### -d, --debug

    [Optional] Sets the logging mode to debug
    
### --set-nx-compat

    [Optional] Sets the NX_COMPAT flag. returns <file>_nx_set.<filetype>

### --clear-nx-compat

    [Optional] Clears the NX_COMPAT flag. returns <file>_nx_clear.<filetype>

### --get-nx-compat

    [Optional] Returns the value of the NX_COMPAT flag

### Status codes returned

    0 - All tests returned pass or warn
    1 - One or more tests returned fail, or an error has occurred

## Tests

### 1. Section Data / Code Separation Verification

Description:

- This test ensures that each section of the binary is not both write-able and
execute-able. Sections can only be one or the other (or neither). This test is
done by iterating over each section and checking the characteristics label for
the Write Mask (0x80000000) and Execute Mask (0x20000000).

Output:

- @Pass: Only one (or neither) of the two masks (Write, Execute) are present
- @Skip: Test Skipped per profile configuration
- @Fail: Both of the two masks (Write, Execute) are set on at least one section

### 2. Section Alignment Verification

Description:

- This test checks the section alignment value found in the optional header.
It must meet the requirements specified in the profile configuration.

Output:

- @Pass: The Image alignment passes all requirements specified in the profile configuration
- @Warn: The Image alignment is not found in the optional header
- @Skip: No image alignment requirements are specified in the profile configuration
- @Fail: The Image alignment does not meet at least one of the requirements
specified in the profile configuration

### 3. Subsystem Type Verification

Description:

- This check verifies the subsystem value found in the optional header.
It must be one of the subsystem types specified in the profile configuration

Output:

- @Pass: The subsystem is one of the types specified in the profile configuration
- @Warn: The subsystem is not found in the optional header
- @Skip: There are no subsystem restrictions in the profile configuration
- @Fail: The subsystem is not one of the types specified in the profile configuration

## Profile Configurations

Configurations are first split by the target architecture, which is determined
from parsing the PE/COFF file. The profile must be specified by the user, or
the default, most restrictive, profile will automatically be used.

### X64 Profiles

- DEFAULT
  - Write / Execute Separation = Required
  - Alignment = 4096
  - Subsystem = Boot Service Driver, ROM
- APP
  - Write / Execute Separation = Required
  - Alignment = 4096
  - Subsystem = Application
- DRIVER
  - Write / Execute Separation = Required
  - Alignment = 4096
  - Subsystem = Boot Service Driver, Runtime Driver, ROM
- PEI
  - Write / Execute Separation = Required
  - Alignment = 4096
  - Subsystem = Boot Service Driver, ROM

### IA32 Profiles

- DEFAULT
  - Write / Execute Separation = Required
  - Alignment = 4096
  - Subsystem = Boot Service Driver, ROM
- APP
  - Write / Execute Separation = Required
  - Alignment = 4096
  - Subsystem = Application
- DRIVER
  - Write / Execute Separation = Required
  - Alignment = 4096
  - Subsystem = Boot Service Driver, Runtime Driver, ROM
- PEI
  - Write / Execute Separation = Required
  - Alignment = 4096
  - Subsystem = Boot Service Driver, ROM

### AARCH64 Profiles

- DEFAULT
  - Write / Execute Separation = Required
  - Alignment = 32, 64
  - Subsystem = Boot Service Driver, ROM
- APP
  - Write / Execute Separation = Required
  - Alignment = 64
  - Subsystem = Application
- DRIVER
  - Write / Execute Separation = Required
  - Alignment = 64
  - Subsystem = Boot Service Driver, Runtime Driver, ROM
- PEI
  - Write / Execute Separation = Required
  - Alignment = 32
  - Subsystem = Boot Service Driver, ROM

### ARM Profiles

- DEFAULT
  - Write / Execute Separation = Required
  - Alignment = 32, 64
  - Subsystem = Boot Service Driver, ROM
- APP
  - Write / Execute Separation = Required
  - Alignment = 64
  - Subsystem = Application
- DRIVER
  - Write / Execute Separation = Required
  - Alignment = 64
  - Subsystem = Boot Service Driver, Runtime Driver, ROM
- PEI
  - Write / Execute Separation = Required
  - Alignment = 32
  - Subsystem = Boot Service Driver, ROM
