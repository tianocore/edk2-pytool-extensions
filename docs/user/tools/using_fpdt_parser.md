# Firmware Performance Data Table (FPDT) Parser Tool

## Overview of UEFI Performance Tables

Analyzing UEFI performance is critical for understanding and optimizing the boot process of a system. The Firmware
Performance Data Table (FPDT) and Firmware Basic Performance Table (FBPT) are the primary ACPI tables used by UEFI
firmware to store performance metrics related to the boot process. The `fpdt_parser.py` tool is designed to parse the
FPDT and FBPT data from a Windows system. It extracts performance records, such as boot times and event timestamps, and
outputs the results in human-readable formats like text or XML.

For more information about the FPDT and FBPT, refer to the ACPI Specification:

- [ACPI 6.5 Specification](https://uefi.org/specs/ACPI/6.5_A)
- [ACI 6.5 Specification - FPDT Section](https://uefi.org/specs/ACPI/6.5_A/05_ACPI_Software_Programming_Model.html#firmware-performance-data-table-fpdt)
- [ACPI 6.5 Specification - FBPT Section](https://uefi.org/specs/ACPI/6.5_A/05_ACPI_Software_Programming_Model.html#firmware-basic-boot-performance-table)

## How to Use

### Prerequisites

- Ensure you have Python installed on your system.
- The tool is designed to run on Windows systems.
- Administrative privileges may be required to access firmware tables.

### Command-Line Arguments

The `fpdt_parser.py` tool accepts the following arguments:

- `-t` or `--output_text`: Specifies the name of the output text file to store the parsed FPDT information.
- `-x` or `--output_xml`: Specifies the name of the output XML file to store the parsed FPDT information.
- `-b` or `--input_bin`: Specifies the name of the input binary file containing the FBPT data. If not provided, the
  tool will attempt to retrieve the data directly from the system firmware.

### Steps to Run

1. Open a command prompt with administrative privileges.
2. Navigate to the directory containing `fpdt_parser.py`.
3. Execute the script with the desired arguments. For example, this will dump the data to an XML file:

   ```cmd
   python fpdt_parser.py  -x output.xml
   ```

4. View the Results:

   - The tool will generate the specified output files containing the parsed FPDT and FBPT data.
   - If no binary file was provided, the tool will log the retrieved data and save it in the specified formats.

### Example Output

- **Text File**:
  The text file will contain detailed information about the UEFI version, model, and performance records.

- **XML File**:
  The XML file will store the same information in a structured format, suitable for further processing or analysis.
  In particular, the XML file can be directly provided as input to the `perf_report_generator.py` tool for generating
  a performance report.

### Troubleshooting

- Run the tool with administrative privileges if accessing the performance data directly from the operating system.
- If using an input FBPT binary, ensure the input binary file exists and is correctly named.
