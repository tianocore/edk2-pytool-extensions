# Windows Firmware Policy Command-Line Tool

A simple command-line interface to the Windows Firmware Policy Library.

## Usage info

General:

``` cmd
firmware_policy_tool <action> <positional_parameter1> ... [-optional_parameter1] ...
```

Enumerating the supported actions and parameters for those actions:

``` cmd
firmware_policy_tool -h

firmware_policy_tool <action> -h

firmware_policy_tool create -h
usage: firmware_policy_tool create [-h] [--OEM1 OEM1] [--OEM2 OEM2]
                                      PolicyFilename Manufacturer Product
                                      SerialNumber NonceHex DevicePolicyHex

positional arguments:
  PolicyFilename   The name of the binary policy file to create
  Manufacturer     Manufacturer Name, for example, "Contoso Computers, LLC".
                   Should match the EV Certificate Subject CN="Manufacturer"
  Product          Product Name, for example, "Laptop Foo"
  SerialNumber     Serial Number, for example "F0013-000243546-X02". Should
                   match SmbiosSystemSerialNumber, SMBIOS System Information
                   (Type 1 Table) -> Serial Number
  NonceHex         The nonce in hexadecimal, for example "0x0123456789abcdef"
  DevicePolicyHex  The device policy in hexadecimal, for example to clear the
                   TPM and delete Secure Boot keys: 0x3

optional arguments:
  -h, --help       show this help message and exit
  --OEM1 OEM1      Optional OEM Field 1, an arbitrary length string, for
                   example "ODM foo"
  --OEM2 OEM2      Optional OEM Field 2, an arbitrary length string
```

Examples of ```create``` to create an unsigned Windows Firmware Policy binary blob,
and ```parse``` to parse an unsigned Windows Firmware Policy binary blob and print it in human understandable form.

``` cmd
firmware_policy_tool create .\test.bin "Contoso LLC." "Laptop Pro" "000-0012345-00S" 0x1a2b3c4d5e6f7890 0x3 --OEM1 "ODM Number One"

firmware_policy_tool parse .\test.bin
```
