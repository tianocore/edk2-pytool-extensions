# UEFI Secure Boot Database Inspection Tool

A simple command-line interface to the UEFI Secure Boot Database Library focused on database inspection

## Usage info

``` cmd
usage: sig_db_tool [-h] [--compact] {dump,get_dupes,get_canonical} ...

UEFI Signature database inspection tool

positional arguments:
  {dump,get_dupes,get_canonical}
    dump                Print a UEFI Signature Database as-is in human-readable form
    get_dupes           Find duplicate signature entries in a UEFI Signature Database. The test for duplication ignores SignatureOwner, testing only the SignatureData
                        field. Print them in UEFI Signature Database format, ordering is NOT maintained, output is NOT itself deduplicated
    get_canonical       Reduce a UEFI Signature Database to a canonical (de-duplicated, sorted) form and print it

optional arguments:
  -h, --help            show this help message and exit
  --compact             Compact, 1 line per data element output for easier diff-ing

examples:

sig_db_tool dump dbx_before.bin

sig_db_tool --compact dump dbx_after.bin

sig_db_tool --compact get_dupes dbx_with_dupes.bin

sig_db_tool --compact get_canonical mixed_up_dbx.bin

```