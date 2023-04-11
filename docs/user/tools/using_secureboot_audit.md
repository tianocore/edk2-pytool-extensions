# Secure Boot Audit Tool

This tool exists to help a user audit the secure boot revocation list (dbx) on their system.

Limitations:

1. Currently only supports windows
2. The audit is only as good as the uefi.org csv file

This tool has three primary stages:

 1. Get the dbx from UEFI
 2. Convert the [UEFI.org csv (xlsx)](https://uefi.org/revocationlistfile) of revocations to json format for comparison
 3. Parse the dbx file and compare it against the uefi.org revocation sheet

## Stage 1 (Retrieve the dbx file from your system)

 Retrieve the dbx file from your system (As of right now this only works on Windows based systems)

    ```bash
    python SecureBootReport.py get dbx
    INFO:root:Wrote .\SecureBootFiles\dbx.bin
    ```

The dbx.bin file retrieved is the pure contents of the dbx file. (I.E it is unsigned).

## Stage 2 (Convert the UEFI.org Excel Sheet)

    ```bash
    python SecureBootReport.py convert_file dbx_info_2020_2023_uefiorg_v3.xlsx
    INFO:root:Wrote report to .\SecureBootFiles\uefi_org_revocations.json
    ```

Flags:

 1. `--output` [not required] - allows for redirection of the output to a new path and name

## Stage 3 (Parse the dbx using the revocations list)

    ```bash
    python secureboot_audit.py parse_dbx dbx.bin uefi_org_revocations.json --filter-by-arch x86_64
    INFO:root:Wrote report to .\SecureBootFiles\dbx_report.json
    ```

### Understanding the output

    ```json
    {
            "identified": {
            "dict": {
                "C805603C4FA038776E42F263C604B49D96840322E1922D5606A9B0BBB5BFFE6F": {
                    "flat_hash_sha256": "2DF05C41ACC56D0F4C9371DA62EC6CB311C9AFB84B4A4D8C3738583CCC874D38",
                    "component": "BOOTX64.EFI",
                    "arch": "x86_64",
                    "partner": " Cisco Systems Inc.",
                    "type": "authenticode",
                    "cves": "CVE-2020-10713; CVE-2020-14308; CVE-2020-14309; CVE-2020-14310; CVE-2020-14311; CVE-2020-15705; CVE-2020-15706; CVE-2020-15707",
                    "date": "July 2020",
                    "authority": "Microsoft Corporation UEFI CA 2011",
                    "links": [
                        "https://nvd.nist.gov/vuln/detail/CVE-2020-10713",
                        "https://nvd.nist.gov/vuln/detail/CVE-2020-14308",
                        "https://nvd.nist.gov/vuln/detail/CVE-2020-14309",
                        "https://nvd.nist.gov/vuln/detail/CVE-2020-14310",
                        "https://nvd.nist.gov/vuln/detail/CVE-2020-14311",
                        "https://nvd.nist.gov/vuln/detail/CVE-2020-15705",
                        "https://nvd.nist.gov/vuln/detail/CVE-2020-15706",
                        "https://nvd.nist.gov/vuln/detail/CVE-2020-15707"
                    ]
                }, // ...
            },
            "total": 183,
            "note": "Represents all the hashes found in a systems dbx that match a provided revocation"
        },
        "missing_protections": {
            "dict": {
                "56FB79AAB26EE9D0E0CA372FB86A8BB459ACBC505D0AB35E6A632A3D5F88DCB3": {
                    "flat_hash_sha256": "AA6F27B8B2CA5826F497362042C003B5E1D7CA22383D82730FBC5C45E048D839",
                    "component": "bootia32.efi",
                    "arch": "x86",
                    "partner": "Neverware",
                    "type": "authenticode",
                    "cves": "CVE-2020-10713; CVE-2020-14308; CVE-2020-14309; CVE-2020-14310; CVE-2020-14311; CVE-2020-15705; CVE-2020-15706; CVE-2020-15707",
                    "date": "July 2020",
                    "authority": "Microsoft Corporation UEFI CA 2011",
                    "links": [
                        "https://nvd.nist.gov/vuln/detail/CVE-2020-10713",
                        "https://nvd.nist.gov/vuln/detail/CVE-2020-14308",
                        "https://nvd.nist.gov/vuln/detail/CVE-2020-14309",
                        "https://nvd.nist.gov/vuln/detail/CVE-2020-14310",
                        "https://nvd.nist.gov/vuln/detail/CVE-2020-14311",
                        "https://nvd.nist.gov/vuln/detail/CVE-2020-15705",
                        "https://nvd.nist.gov/vuln/detail/CVE-2020-15706",
                        "https://nvd.nist.gov/vuln/detail/CVE-2020-15707"
                    ]
                }, // ...
            },
            "total": 54,
            "note": "The remaining hashes in the provided revocation list that were not found in the system dbx"
        },
        "not_found": {
            "list": [
                "F52F83A3FA9CFBD6920F722824DBE4034534D25B8507246B3B957DAC6E1BCE7A",
                // ...
            ],
            "total": 84,
            "note": "The hashes that were found in the dbx that are not in the provided revocation list"
        }
    }
    ```

The output is broken up into three sections:

 1. `identified` - All the revocations in a system's dbx that match a revocation provided in revoction list
 2. `missing_protections` - All the revocations that were provided in a revocation list that do not appear in a system's
dbx
 3. `not_found` - All the revocations that were in the dbx, but were not in a provided revocation list

Flags:

 1. `--output` [not required] - allows for redirection of the output to a new path and name
 2. `--format` [not required] - this allows the script to switch the output between `json` and `xlsx` format
 3. `--filter-by-arch` [not required] - this allows the script to filter by `x86`, `x86_64`, `arm`, `arm64` or if left off
 `None`
