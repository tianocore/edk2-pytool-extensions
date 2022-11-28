# Version Info Tool

A simple command line utility for working with resource sections and PECOFF binaries.
Utility can dump the contents of a PECOFF RSRC section into readable json data
Utility can encode a json file with name/value pairs into a input file for a RC compiler.

!!! warning "BETA feature"
    This tools is part of a proof of concept project to support embedding version
    information into UEFI PE images.  As this project advances this may require
    changes of this tool as well as significant refactoring.  Overall,
    expect the versioninfo module and cli to be less stable than other parts
    of pytools.

## Usage info

run `versioninfo_tool -h`

``` cmd
usage: versioninfo_tool [-h] [-e | -d] input_file output_file

Versioninfo Tool is a command-line tool to assist in generating VERSIONINFO
resource files for use with a Resource Compiler. It takes a JSON representing
versioning info and produces a resource file that once compiled will create a
standard resource section.

!!! Warning - BETA Feature
This tool is still in early development and may change with
little regard for backward compatibility.

Version: 0.7.0

An example to encode json to rc file might look like:
versioninfo_tool -e /path/to/version.JSON /path/to/output

An example to decode a binary efi file and output the rsrc in json might look like:
versioninfo_tool -d /path/to/app.efi /path/to/output.JSON

positional arguments:
  input_file    a filesystem path to a json/PE file to load
  output_file   a filesystem path to the output file. if file does not exist, entire directory path will be created. if
                file does exist, contents will be overwritten

optional arguments:
  -h, --help    show this help message and exit
  -e, --encode  (default) outputs VERSIONINFO.rc of given json file
  -d, --dump    outputs json file of VERSIONINFO given PE file

```

## JSON file format

The json input file used for the ecode operation can be in two flavors.
First a minimal file.  This must contain only these three fields.

```json
{
  "FileVersion": "1.0.0.0",
  "CompanyName": "Example Company",
  "OriginalFilename": "ExampleApp.efi"
}
```

or if `Minimal` is set to "False" then the json must contain the values for a complete rc section.

```json
{
  "Minimal": "False",
  "FileVersion": "1.0.0.0",
  "ProductVersion": "1.0.0.0",
  "FileFlagsMask": "VS_FFI_FILEFLAGSMASK",
  "FileFlags": "0",
  "FileOS": "VOS_NT",
  "FileType": "VFT_DRV",
  "FileSubtype": "VFT2_DRV_SYSTEM",
  "StringFileInfo": {
      "CompanyName": "Example Company",
      "OriginalFilename": "ExampleApp.efi",
      "FileVersion": "1.0.0.0",
  },
  "VarFileInfo": {
    "Translation": "0x0409 0x04b0"
  }
}
```

## More Info

<https://docs.microsoft.com/en-us/windows/win32/menurc/versioninfo-resource>
