# @file usage_report.py
# A report that generates an html report about which repositories INFs (That are consumed for a platform) originate
# from.
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""A report that generates an html report about which repositories INFs originate from."""
import io
import logging
import pathlib
from argparse import ArgumentParser, Namespace

from edk2toollib.database import Edk2DB

from edk2toolext.environment.reporttypes import templates
from edk2toolext.environment.reporttypes.base_report import Report

QUERY = """
WITH variable AS (
    SELECT
        ? AS env -- VARIABLE: Change this to the environment parse you care about
)
SELECT DISTINCT
    package.repository AS "Repository",
    inf.package AS "Package",
    inf_list.path AS "INF Path",
    junction.key2 AS "Source Path",
    source.total_lines AS "Code Line Count",
    CASE
        WHEN inf.library_class IS NULL THEN TRUE
        ELSE FALSE
    END AS "Component"
FROM
    (
        SELECT
            DISTINCT instanced_inf.path
        FROM
            variable,
            instanced_fv
            JOIN junction ON instanced_fv.env = junction.env
            AND junction.table1 = 'instanced_fv'
            AND junction.table2 = 'inf'
            JOIN instanced_inf ON instanced_inf.component = junction.key2
        WHERE
            instanced_fv.env = variable.env
    ) inf_list,
    variable
    JOIN junction ON junction.key1 = inf_list.path
    AND junction.table2 = 'source'
    AND junction.env = variable.env
    LEFT JOIN source ON source.path = junction.key2
    LEFT JOIN inf ON inf.path = inf_list.path
    LEFT JOIN package ON inf.package = package.name
ORDER BY
    package.repository,
    package.name,
    inf_list.path
"""

VERSION_QUERY = """
SELECT version
FROM environment
WHERE id = ?;
"""

ID_QUERY = """
SELECT id
FROM environment
ORDER BY date
DESC LIMIT 1;
"""


COLORS = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b', '#e377c2', '#7f7f7f', '#bcbd22', '#17becf', '#aec7e8', '#ffbb78', '#98df8a', '#ff9896', '#c5b0d5']


class UsageReport(Report):
    """A report that generates a INF usage report for a specific build."""
    def report_info(self):
        """Returns the report standard information.

        Returns:
            (str, str): A tuple of (name, description)
        """
        return ("usage", "Generates a report of INF usage for a specific build.")

    def add_cli_options(self, parserobj: ArgumentParser):
        """Configure command line arguments for this report."""
        parserobj.add_argument("-e", "-env", dest="env_id", action="store",
                               help = "The environment id to generate the report for. Defaults to the latest "
                               "environment.")
        parserobj.add_argument("-o", "-output", dest="output", action="store", default=None,
                               help = "The output file to write the report to. Defaults to 'usage_report.html'.")

    def run_report(self, db: Edk2DB, args: Namespace):
        """Generate the Usage report."""
        try:
            import plotly.graph_objects as go
            from jinja2 import Environment, FileSystemLoader
        except ImportError as e:
            print(e)
            print("WARNING: This report requires pip modules not installed with edk2-pytool-extensions:")
            print("  Run the following command: `pip install jinja2 plotly`")
            exit(-1)

        env_id = args.env_id or db.connection.execute(ID_QUERY).fetchone()[0]
        reports, inf_list = self.generate_data(env_id, db)

        # Build color map for consistent colors across all reports
        color_map = {}
        for idx, key in enumerate({item[0] for item in inf_list}):
            color_map[key] = COLORS[idx % len(COLORS)]

        # Vars for html template
        env = Environment(loader=FileSystemLoader(templates.__path__))
        template = env.get_template("usage_report_template.html")
        report_data = {
            "version": db.connection.execute(VERSION_QUERY, (env_id,)).fetchone()[0],
            "env": self._get_env_vars(db.connection, env_id),
            "inf_list":  inf_list,
        }

        # Build the pie charts and save them in report_data
        for key, value, title, combine in reports:
            labels = [key for key in value.keys()]
            if combine:
                values = [len(set(value)) for value in value.values()]
            else:
                values = [value[key] for key in value.keys()]
            fig = go.Figure(go.Pie(labels=labels, values=values, hole = .3, title=title, titleposition="top center"))
            fig.update_traces(marker=dict(colors=[color_map[key] for key in value.keys()]))
            # Write the html
            html = io.StringIO()
            fig.write_html(html, full_html=False, include_plotlyjs=False)
            html.seek(0)

            # Add the html to the data dictionary
            report_data[key] = html.read()

        # Open the template and write the html with the report data
        html_output = template.render(**report_data)
        path_out = args.output or report_data["env"].get("PLATFORM_NAME", None) or "usage_report.html"
        if not path_out.endswith(".html"):
            path_out += ".html"

        pathlib.Path(path_out).parent.mkdir(exist_ok=True, parents=True)
        with open(path_out, 'w') as f:
            f.write(html_output)
        logging.info(f"Report written to {path_out}.")

    def generate_data(self, env_id, db) -> tuple[dict, set]:
        """Generates a list of pie chart data.

        Args:
            env_id (int): The environment id the report is generating off of.
            db (Edk2DB): The database to pull data from.

        Returns:
            (dict, set): (pie chart data, set of all INFs)
        """
        lib_infs = {}
        comp_infs = {}
        total_infs = {}
        lib_lines = {}
        comp_lines = {}
        total_lines = {}

        inf_dict = {}
        for repo, package, inf, _src, line_count, is_component in db.connection.execute(QUERY, (env_id,)).fetchall():
            key = (repo, package, inf)
            current = inf_dict.setdefault(key, (repo, package, inf, 0))
            inf_dict[key] = (repo, package, inf, current[3] + (line_count or 0))

            if is_component:
                inf_d = comp_infs
                src_d = comp_lines
            else:
                inf_d = lib_infs
                src_d = lib_lines

            inf_d.setdefault(repo, []).append(inf)
            src_d[repo] = src_d.get(repo, 0) + (line_count or 0)

        total_infs = self._merge_dicts(lib_infs, comp_infs)
        total_lines = self._merge_dicts(lib_lines, comp_lines)

        # Build the reports
        reports = [
            ("total_pie_chart", total_infs, "Total INF Usage Per Repository", True),
            ("lib_pie_chart", lib_infs, "Library Usage Per Repository", True),
            ("comp_pie_chart", comp_infs, "Component Usage Per Repository", True),
            ("total_src_pie_chart", total_lines, "Total Line Count Per Reporitory", False),
            ("lib_src_pie_chart", lib_lines, "Library Line Count Per Repository", False),
            ("comp_src_pie_chart", comp_lines, "Component Line Count Per Repository", False),
        ]
        return (reports, set(inf_dict.values()))

    def _get_env_vars(self, connection, env_id):
        env_vars = {}
        results = connection.execute("SELECT key, value FROM environment_values WHERE id = ?;", (env_id,)).fetchall()
        for key, value in results:
            env_vars[key] = value
        return env_vars

    def _merge_dicts(self, dict1, dict2) -> dict:
        return_dict = {}
        for key in dict1:
            if key in dict2:
                return_dict[key] = dict1[key] + dict2[key]
            else:
                return_dict[key] = dict1[key]
        for key in dict2:
            if key not in return_dict:
                return_dict[key] = dict2[key]
        return return_dict
