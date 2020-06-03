# @file generate.py
# Generates the documentation for this repo
#
#
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import os
import sys
import argparse
import glob
import logging
import yaml
import shutil
import pkg_resources
from mike import commands as mike_commands
from mike import mkdocs as mike_mkdocs
from mike import git_utils
from mkdocs.commands.serve import _static_server as mkdocs_serve
from pdocs import as_markdown as pdocs_as_markdown
from io import StringIO

project_config = {
    "site_name": None,
    "repo_url": None,
    "copyright": None,
    "site_description": None,
    "site_url": None,
    "plugins": ["search", ],  # "macros"],

    "theme": {
        "name": 'material',
        "palette": {
            "primary": 'indigo',
            "accent": 'indigo'
        }
    },
    "markdown_extensions": [
        "admonition",
        "codehilite",
        "meta",
        {
            "pymdownx.betterem": {
                "smart_enable": "all",
            },
        },
        "pymdownx.caret",
        "pymdownx.critic",
        "pymdownx.details",
        {
            "pymdownx.emoji": {
                "emoji_generator": "!!python / name: pymdownx.emoji.to_png",
            },
        },
        "pymdownx.inlinehilite",
        "pymdownx.magiclink",
        "pymdownx.mark",
        "pymdownx.smartsymbols",
        "pymdownx.superfences",
        {
            "pymdownx.tasklist": {
                "custom_checkbox": True,
            },
        },
        "pymdownx.tilde",
        {
            "toc": {
                "permalink": True,
            }
        },
        "markdown.extensions.abbr",
        "markdown.extensions.admonition",
        "markdown.extensions.attr_list",
        "markdown.extensions.def_list",
        "markdown.extensions.fenced_code",
        "markdown.extensions.footnotes",
        "markdown.extensions.tables",
        "markdown.extensions.smarty",
        "markdown.extensions.toc",
    ],
    "nav": [
        {
            "Home": "index.md"
        }
    ]
}


#
# When generating the nav convert visible names
# to something more human readable
#
# Currently support changing snake_case and CamelCase
#
def ConvertToFriendlyName(string):
    if string.lower().endswith(".md"):
        string = string[:-3]
    string = string.replace("_", " ").strip()  # strip snake case
    string = ' '.join(string.split())  # strip duplicate spaces

    # Handle camel case
    newstring = ""
    prev_char_lowercase = False
    for i in string:
        if(not prev_char_lowercase):
            newstring += i
        else:
            if(i.isupper()):
                newstring += " " + i
            else:
                newstring += i
        prev_char_lowercase = i.islower()

    return newstring.capitalize()


def parse_arguments(args=None):
    parser = argparse.ArgumentParser(description="Generates the python documentation")
    '''
    Manual: A user manually queued the build.
    IndividualCI: Continuous integration (CI) triggered by a Git push or a TFVC check-in.
    BatchedCI: Continuous integration (CI) triggered by a Git push or a TFVC check-in, and the Batch changes was selected.
    Schedule: Scheduled trigger.
    ValidateShelveset: A user manually queued the build of a specific TFVC shelveset.
    CheckInShelveset: Gated check-in trigger.
    PullRequest: The build was triggered by a Git branch policy that requires a build.
    BuildCompletion: The build was triggered by another build.
    ResourceTrigger: The build was triggered by a resource trigger.
    '''
    parser.add_argument("--reason", "-r", type=str, dest="reason", default="Manual")
    parser.add_argument("--workspace", "-ws", type=str, dest="ws", default=os.getcwd())
    parser.add_argument("--output_dir", "-o", type=str, dest="output_dir", default="doc_output")
    parser.add_argument("--module", "-m", type=str, dest="module")
    parser.add_argument("--docs", "-d", type=str, dest="src_docs", action='append')
    parser.add_argument("--serve", "-s", dest="serve", default=False, action='store_true')
    parser.add_argument("--verbose", "-v", dest="verbose", action="store_true", default=False)
    parser.add_argument("--deploy", "-deploy", dest="deploy", action="store_true", default=False)
    parser.add_argument("--include-tests", dest="include_tests", action="store_true", default=False)
    parser.add_argument("--version", dest="version", type=str, default=None)
    options = validate_arguments(vars(parser.parse_args(args=args)))
    return options

def validate_arguments(options):
    valid_reasons = ['Manual', 'IndividualCI', 'BatchedCI', 'Schedule', 'ValidateShelveset',
                     'CheckInShelveset', 'PullRequest', 'BuildCompletion', 'ResourceTrigger', ]
    if "reason" not in options or options["reason"] not in valid_reasons:
        logging.error(f"{options['reason']} is not a valid reason")
        sys.exit(1)
    if options["module"] is None:
        # TODO figure out what module we are in?
        options["module"] = "edk2toollib"
    ws = options["ws"]
    if not os.path.isabs(options["output_dir"]):
        options["output_dir"] = os.path.abspath(os.path.join(ws, options["output_dir"]))
    options["html_dir"] = os.path.abspath(os.path.join(options["output_dir"], "html"))
    options["docs_dir"] = os.path.abspath(os.path.join(options["output_dir"], "docs"))
    if os.path.exists(options["output_dir"]):
        shutil.rmtree(options["output_dir"], ignore_errors=False)
    os.makedirs(options["output_dir"], exist_ok=True)
    os.makedirs(options["html_dir"], exist_ok=True)
    os.makedirs(options["docs_dir"], exist_ok=True)
    return options


def generate_config_file(options):
    config_path = os.path.join(options["output_dir"], "mkdocs.yml")
    project_config["docs_dir"] = options["docs_dir"]
    project_config["site_dir"] = options["html_dir"]
    with open(config_path, "w") as yaml_file:
        yaml.dump(project_config, yaml_file)  # , default_flow_style=False)
    if options["verbose"]:
        print(f"Generating config file {config_path}")
    mike_commands.install_extras(config_path, theme="material")
    return config_path


def generate_pdoc_markdown(options):
    pdocs_as_markdown([options["module"], ], options["docs_dir"], overwrite=True)
    print("Finished PDoc")
    if not options["include_tests"]:
        # if we aren't including any tests
        print("Removing test documentation")
        search_paths = [os.path.join("**", "*_test.md"), os.path.join("**", "test_*.md"),
                        os.path.join("**", "test", "*.md")]
        for search_path in search_paths:
            docs = glob.iglob(os.path.join(options["docs_dir"], search_path), recursive=True)
            for doc in docs:
                if options["verbose"]:
                    print(f"Removing test documentation at {doc}")
                os.remove(doc)


def run_mkdocs(options):
    project_config["config_file_path"] = generate_config_file(options)
    mike_mkdocs.build(project_config["config_file_path"])


def handle_glob(glob_iter, src_folder, dst_folder):
    for doc in glob_iter:
        rel_path = os.path.relpath(doc, src_folder)
        rel_dir = os.path.dirname(rel_path)
        output_dir = os.path.join(dst_folder, rel_dir)
        outfile = os.path.join(output_dir, os.path.basename(doc))
        os.makedirs(output_dir, exist_ok=True)
        if os.path.exists(outfile):
            logging.warning(f"Overwritting {outfile}")
            raise ValueError()
        shutil.copy2(doc, outfile)


def copy_docs(options):
    # first copy the readme if needed
    root_files = ["readme.md", "license.txt"]
    for root_filename in root_files:
        root_infile = os.path.join(options["ws"], root_filename)
        if root_filename == "readme.md":
            root_filename = "index.md"
        root_outfile = os.path.join(options["docs_dir"], root_filename)
        if os.path.exists(root_infile):
            shutil.copy2(root_infile, root_outfile)

    # copy any files from the code tree
    module_path = os.path.join(options["ws"], options["module"])
    if os.path.exists(module_path):
        search_path = os.path.join(module_path, "**", "*.md")
        docs = glob.iglob(search_path, recursive=True)
        handle_glob(docs, options["ws"], options["docs_dir"])

    # copy any doc folders
    docs_folder = os.path.join(options["ws"], "docs")
    if options["src_docs"] == None:
        options["src_docs"] = []
    if os.path.exists(docs_folder) and docs_folder and docs_folder not in options["src_docs"]:
        options["src_docs"].append(docs_folder)

    for src_folder in options["src_docs"]:
        src_folder = os.path.join(options["ws"], src_folder)
        if not os.path.exists(src_folder):
            raise ValueError(f"Bad path: {src_folder}")
        search_path = os.path.join(src_folder, "**", "*.md")
        docs = glob.iglob(search_path, recursive=True)
        handle_glob(docs, src_folder, options["docs_dir"])


def collapse_docs(options):
    # look for any directory that has both a index and a readme in it- merge them into index.md
    # index = index + readme (index comes first)
    for root, _, files in os.walk(options["docs_dir"]):
        if "index.md" in files and "readme.md" in files:
            with open(os.path.join(root, "index.md"), "a") as index:
                with open(os.path.join(root, "readme.md"), "r") as readme:
                    lines = readme.readlines()
                    index.write("\n")
                    index.writelines(lines)
            os.remove(os.path.join(root, "readme.md"))


def generate_nav(options):
    search_path = os.path.join(options["docs_dir"], "*.md")
    root_docs = glob.iglob(search_path, recursive=False)
    for doc in root_docs:
        doc_path = os.path.basename(doc)
        if doc_path == "index.md":
            continue
        doc_name = ConvertToFriendlyName(doc_path)
        link = {doc_name: doc_path}
        project_config["nav"].append(link)
    # now look at docs from docs folder
    directories = [f for f in os.listdir(options["docs_dir"]) if os.path.isdir(os.path.join(options["docs_dir"], f))]
    for directory in directories:
        if directory == options["module"]:
            continue
        folder_name = ConvertToFriendlyName(directory)
        nav_links = []
        directory_path = os.path.join(options["docs_dir"], directory)
        files = [f for f in os.listdir(directory_path) if f.lower().endswith(".md")]
        for mdfile in files:
            file_name = ConvertToFriendlyName(mdfile)
            file_path = os.path.relpath(os.path.join(directory_path, mdfile), options["docs_dir"])
            nav_links.append({file_name: file_path})
        project_config["nav"].append({folder_name: nav_links})
    # now get auto generated docs from the module
    tree = {}
    search_root = os.path.join(options["docs_dir"], options["module"])
    search_path = os.path.join(search_root, "**", "*.md")
    sub_docs = glob.iglob(search_path, recursive=True)
    for doc in sub_docs:
        doc_filename = os.path.basename(doc)
        doc_name = ConvertToFriendlyName(doc_filename)
        doc_relpath = os.path.relpath(doc, search_root)
        doc_path = os.path.join(options["module"], doc_relpath)
        tree_ptr = tree
        path_parts = doc_relpath.split(os.sep)
        if len(path_parts) == 1:
            tree[doc_name] = doc_path
            continue

        for path_part in path_parts:
            path_part_name = ConvertToFriendlyName(path_part)
            if path_part == "":
                continue
            elif path_part.lower().endswith(".md"):
                tree_ptr[path_part_name] = doc_path
            elif path_part_name not in tree_ptr:
                tree_ptr[path_part_name] = {}
            tree_ptr = tree_ptr[path_part_name]

    def convert_tree(tree):
        links = []
        for item_key in tree:
            item_value = tree[item_key]
            if isinstance(item_value, str):
                links.append({item_key: item_value})
            else:
                links.append({item_key: convert_tree(item_value)})
        return links
    links = convert_tree(tree)
    # convert the tree to the mkdocs nav format
    project_config["nav"].append({"Reference": links})


def serve_docs(options):
    if options["serve"]:
        logging.critical("Serving")
        print("Serving your project. Press Ctrl-C to exit")
        print("Serving at http://localhost:3000")
        mkdocs_serve("localhost", 3000, options["html_dir"])


def get_module_path_and_version(options):
    distro = pkg_resources.get_distribution("edk2-pytool-library")
    return (distro.location, distro.version)


def get_version(options):
    if options["version"] != None:
        return options["version"]
    # we import it here as it may have changed since we imported this script
    from edk2toollib import utility_functions
    location, version = get_module_path_and_version(options)
    try:
        if utility_functions.is_valid_version(version):
            return version
    except:
        pass
    if version.count("+") == 1:
        # we've installed locally
        # figure out what branch we are on?
        out_stream = StringIO()
        utility_functions.RunCmd("git", "describe --tags", workingdir=os.path.dirname(location), outstream=out_stream)
        out_stream.seek(0)
        line = out_stream.readline()
        print(line)
        # Tag should be like v#.#.#
        raise RuntimeError()
        return "master"
    return version


def deploy(options):
    if not options["deploy"]:
        return
    remote = "personal"
    branch = "gh-pages"
    force_push = True
    version = get_version(options)

    logging.critical(f"Deploying {version}")
    mike_commands.deploy(options["html_dir"], version, branch=branch)
    mike_commands.set_default("master", branch=branch)
    git_utils.push_branch(remote, branch, force_push)
    print("Finished deployment")


def main(options=None):
    if options is None:
        options = parse_arguments()
    mod_path, _ = get_module_path_and_version(options)
    # we have to change the current working directory as this can conflict
    cwd = os.getcwd()
    os.chdir(mod_path)
    logging.critical(f"Using module at {mod_path}")

    logging.critical("Generating Python documentation")
    generate_pdoc_markdown(options)
    logging.critical("Copying existing documentation")
    copy_docs(options)
    collapse_docs(options)
    logging.critical("Generating Navigation")
    generate_nav(options)
    logging.critical("Converting to HTML")
    run_mkdocs(options)
    os.chdir(cwd)
    deploy(options)
    serve_docs(options)


if __name__ == "__main__":
    main()
