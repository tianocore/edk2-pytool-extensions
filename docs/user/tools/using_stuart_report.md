# Report Generator Tool

The report generator tool `stuart_report` is a tool that allows you to run
reports on database that was generated via `stuart_parse`. The tool is designed
to be portable, such that it can be ran on a database and the repository the
database was generated from does not have to be present. This is so that
databases can be archived, or passed around, and reports can be generated after
the fact, or used to compare different versions of the firmware.

## Command line arguments

```
positional arguments:
    {...} # List of available reports and a short description

options:
  -h, --help            show this help message and exit
  --verbose, --VERBOSE, -v
                        verbose
  -db DATABASE, --database DATABASE, --DATABASE DATABASE
                        The database to use when generating reports.
```

Review the command line arguments with `stuart_report -h`. As you can tell, the
command line interface for the tool itself is simple, only truly needing a path
to the database to use. Out of convenience, the default path for the databse is
Reports/DATABASE.db, as that is where the database is generated when running
`stuart_parse`. If the database is moved or renamed, you will need to manually
link it with the `-db, --databse`.

Each available report (positional argument) has it's own subset of command line
arguments so before running a report, it is important to review it's interface
also `stuart_report <Report> -h` to see the customizations / necessary
arguments for the report.
