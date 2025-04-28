# Performance Report Generator Tool

## Overview

The `perf_report_generator.py` tool is designed to process Firmware Performance Data Table (FPDT) XML data and generate
a detailed HTML performance report. This tool is particularly useful for analyzing boot performance metrics and
visualizing the data in a structured and user-friendly format.

The generated HTML report includes information such as:

- UEFI version and model details.
- Boot timing events for code sections and functions.
- Boot performance of modules across boot phases.

## How to Use

### Prerequisites

- Ensure you have Python installed on your system.
- You need an XML file containing FPDT data, which can be generated using the `fpdt_parser.py` tool.

### Command-Line Arguments

The `perf_report_generator.py` tool accepts the following arguments:

- `-t` or `--output_text`: Specifies the name of the output text file to store the parsed performance data.
- `-r` or `--output_html`: Specifies the name of the output HTML file to store the performance report.
- `-i` or `--input_xml_file`: Specifies the path to the input XML file containing FPDT data.
- `-s` or `--src_tree_root`: Specifies the root of the UEFI code tree to parse for GUIDs (optional).
- `-d` or `--debug`: Enables debug output for troubleshooting.
- `-l` or `--output_debug_log`: Specifies a file to log all debug and error output.

### Steps to Run

1. Open a command prompt.
2. Execute the script with the desired arguments. For example, to generate an HTML report:

   ```cmd
   python perf_report_generator.py -i input.xml -r report.html
   ```

3. View the Results:
   - The tool will generate the specified output files containing the performance report.
   - The HTML report can be opened in any web browser for visualization.

### Example Output

- **Text File**:
  The text file will contain detailed timing information, including event types, GUIDs, and timestamps.

- **HTML File**:
  The HTML file will present the same information in a structured and interactive format, suitable for analysis and sharing.

### Troubleshooting

- Ensure the input XML file exists and is correctly formatted.
- Use the `-d` flag to enable debug output for troubleshooting issues.
- Check the debug log file (if specified) for detailed error messages.
