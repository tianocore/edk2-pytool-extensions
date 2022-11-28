# Capsule Helper and Tool

These modules are designed to help developers build, sign, and distribute correctly formatted
UEFI Capsules, as well as the Windows files necessary to arm and install the Capsules.

## Capsule Helper Parameters

The CapsuleHelper tool has a number of functions to help build and/or format Capsules
and their associated files. Each of these functions has some associated function documentation,
but there are some shared parameters between all of the functions. These are described here.

### Capsule Options

This is a dictionary that can include the following values:

- `fw_version_string` - must be a string containing the dot-separated semantic version for this
    capsule. Used in file naming and INF file
- `fw_version` - must be a number that can be represented as a 32-bit unsigned integer. Used in
    the capsule binary and INF file
- `is_rollback` - TODO: Document
- `arch` - TODO: Document
- `fw_name` - TODO: Document
- `provider_name` - TODO: Document
- `esrt_guid` - TODO: Document
- `arch` - TODO: Document
- `fw_description` - TODO: Document
- `fw_version_string` - TODO: Document
- `fw_version` - TODO: Document
- `mfg_name` - TODO: Document
- `fw_integrity_file` - if included, must be the filename of a Mu FW integrity file to be included
    with the capsule files. Caller must ensure that the integrity file is in the same directory as
    the newly generated capsule binary. Used by the INF file

### Signer Options

TBD

### Signature Options

TBD
