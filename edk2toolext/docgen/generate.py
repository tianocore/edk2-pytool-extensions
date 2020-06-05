# @file generate.py
# Generates the documentation for this repo
#
#
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import os
import glob
import logging
import yaml
import shutil
import pkg_resources
import re
from mike import commands as mike_commands
from mike import mkdocs as mike_mkdocs
from mkdocs.commands.serve import _static_server as mkdocs_serve
from pdocs import as_markdown as pdocs_as_markdown
import copy
from enum import Enum, auto


class DocGenerator():
    class Hooks(Enum):
        PreSetup = auto(),
        PostSetup = auto(),
        PreModuleParse = auto(),
        PostModuleParse = auto(),
        PreMarkdown = auto(),
        PostMarkdown = auto(),
        PreHtml = auto(),
        PostHtml = auto(),
        PreDeploy = auto(),
        PostDeploy = auto(),
        PreServe = auto(),
        PostServe = auto(),

    def __init__(self):
        self._project_config = {
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
        }
        self._workspace = os.getcwd()
        self._output_dir = "doc_output"
        self._module = None  # this is the module to generate docs for
        self._module_name = None
        self._hooks = {}
        self._verbose = False
        self._should_include_tests = True
        self._doc_folders = []

    def set_workspace(self, ws):
        ''' sets the workspace - this is what the output directory will be relative to '''
        self._workspace = os.path.abspath(ws)

    def set_verbose(self, is_verbose):
        self._verbose = is_verbose

    def _print(self, message):
        if self._verbose:
            print(message)

    def set_output_dir(self, out):
        ''' sets the output directory of the docs and the html. If not an abs path, it will be relative to the workspace '''
        self._output_dir = out

    def set_target_module(self, module, module_name=None):
        '''
        sets the target module
        modules can be a pip module import name or a path
        for example: 
            module="edk2toollib", module_name = "edk2-pytool-library"
        '''
        self._module = module
        self._module_name = module_name

    def set_should_include_test_documentation(self, should_include):
        ''' if we should include the documentation from the tests '''
        self._should_include_tests = should_include

    def set_config_defaults(self, site_name, site_url, repo_url, copyright=None, site_description=""):
        self.set_config("site_name", site_name)
        self.set_config("site_url", site_url)
        self.set_config("repo_url", repo_url)
        self.set_config("copyright", copyright)
        self.set_config("site_description", site_description)

    def set_config(self, key, value):
        self._project_config[key] = value

    def dump_config(self):
        ''' returns a copy of the configuration '''
        return copy.deepcopy(self._project_config)

    @staticmethod
    def ConvertToFriendlyName(path):
        '''
        Convert visible names to something more human readable
        Currently support changing snake_case and CamelCase
        If a markdown path is passed, the heading the file will be used
        '''
        if path == "doc_output":
            raise RuntimeError("This should not be")
        if path.lower().endswith(".md") and os.path.exists(path):
            # Read in the markdown file to see if we can find a heading
            header_re = re.compile(r'(^|\n) ?\# *([\w \d]+)(\n|$)')
            with open(path, "r") as markdown:
                md_lines = markdown.read(600)  # read up to 600 characters
                match = header_re.search(md_lines)
                if match is not None:
                    return match.group(2).strip().title()

        string = os.path.basename(path)
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

        return newstring.title()

    def get_output_dir(self):
        if os.path.isabs(self._output_dir):
            return self._output_dir
        else:
            return os.path.abspath(os.path.join(self._workspace, self._output_dir))

    def get_output_html_dir(self):
        return os.path.join(self.get_output_dir(), "html")

    def get_output_docs_dir(self):
        return os.path.join(self.get_output_dir(), "docs")

    def get_output_config_path(self):
        return os.path.join(self.get_output_dir(), "mkdocs.yml")

    def add_doc_folder(self, folder):
        self._doc_folders.append(folder)

    def set_hook(self, hook_name, callback):
        if hook_name not in self._hooks:
            self._hooks[hook_name] = []
        self._hooks[hook_name].append(callback)

    def _call_hooks(self, hook_name):
        if hook_name not in self._hooks:
            return
        for hook in self._hooks[hook_name]:
            hook()

    def generate(self):
        # Setup
        self._print("Starting document generation")
        self._print("Stage: Pre-Setup")
        self._call_hooks(self.Hooks.PreSetup)
        self._print("Stage: Setup")
        self._setup_workspace()
        self._print("Stage: Post-Setup")
        self._call_hooks(self.Hooks.PostSetup)
        # module parse
        self._print("Stage: Pre-Module-Parse")
        self._call_hooks(self.Hooks.PreModuleParse)
        self._print("Stage: Module-Parse")
        self._module_parse()
        self._print("Stage: Post-Module-Parse")
        self._call_hooks(self.Hooks.PostModuleParse)
        # Markdown
        self._print("Stage: Pre-Markdown")
        self._call_hooks(self.Hooks.PreMarkdown)
        self._print("Stage: Markdown")
        self._markdown_consolidate()
        self._print("Stage: Post-Markdown")
        self._call_hooks(self.Hooks.PostModuleParse)
        # Navigation generation
        self._print("Stage: Navigation")
        self._nav_generation()
        # Html
        self._print("Stage: Pre-HTML")
        self._call_hooks(self.Hooks.PreHtml)
        self._print("Stage: HTML")
        self._html()
        self._print("Stage: Post-HTML")
        self._call_hooks(self.Hooks.PostHtml)

    def _setup_workspace(self):
        if os.path.exists(self.get_output_dir()):
            shutil.rmtree(self.get_output_dir(), ignore_errors=False)
        os.makedirs(self.get_output_dir(), exist_ok=True)
        os.makedirs(self.get_output_html_dir(), exist_ok=True)
        os.makedirs(self.get_output_docs_dir(), exist_ok=True)
        # check that we have the module
        if self._module is None:
            raise ValueError("You must call set_target_module before generate")
        # check if our config is valid
        if not self._validate_config():
            raise ValueError("The markdown configuration is invalid")

    def _write_config(self):
        # output the config file
        config_path = self.get_output_config_path()
        self.set_config("config_file_path", config_path)
        self.set_config("docs_dir", self.get_output_docs_dir())
        self.set_config("site_dir", self.get_output_html_dir())
        with open(config_path, "w") as yaml_file:
            yaml.dump(self._project_config, yaml_file)  # , default_flow_style=False)
        mike_commands.install_extras(config_path, theme="material")

    def _module_parse(self):
        # set our workind directory while this is parsing
        cwd = os.getcwd()
        if self._module_name is not None:
            distro = pkg_resources.get_distribution(self._module_name)
            self._print(f"Switching to {distro.location}")
            os.chdir(distro.location)
        try:
            pdocs_as_markdown([self._module, ], self.get_output_docs_dir(), overwrite=True)
        except SystemExit:
            print("Error - There was likely an error loading one the of the files in this module. Check you have all the required modules.")
            raise
        os.chdir(cwd)

    def _validate_config(self):
        if "site_name" not in self._project_config:
            return False
        # TODO: leverage the mkdocs config validation already
        return True

    @staticmethod
    def _handle_glob(glob_iter, src_folder, dst_folder):
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

    @staticmethod
    def _glob_for_all_of_type(src_folder, dst_folder, extensions=None, recursive=True):
        if extensions is None:
            extensions = ["png", "md", "jpg", "txt"]
        for ext in extensions:
            if recursive:
                search_path = os.path.join(src_folder, "**", f"*.{ext}")
            else:
                search_path = os.path.join(src_folder, f"*.{ext}")
            docs = glob.iglob(search_path, recursive=recursive)
            DocGenerator._handle_glob(docs, src_folder, dst_folder)

    def _markdown_consolidate(self):
        docs_dir = self.get_output_docs_dir()
        module_folder = os.path.basename(self._module)

        # delete any test documentation if configured that way
        if not self._should_include_tests:
            self._remove_test_documentation()
        # first copy the readme if needed
        root_files = ["readme.md", "license.txt", "LICENSE"]
        for root_filename in root_files:
            root_infile = os.path.join(self._workspace, root_filename)
            if root_filename == "readme.md":
                root_filename = "index.md"
            if not root_filename.endswith(".txt") and not root_filename.endswith(".md"):
                root_filename += ".txt"
            root_outfile = os.path.join(docs_dir, root_filename)
            if os.path.exists(root_infile):
                shutil.copy2(root_infile, root_outfile)

        # copy any images
        self._glob_for_all_of_type(self._workspace, self.get_output_docs_dir(),
                                   extensions=["png", "jpg"], recursive=False)

        # copy any files from the code tree
        module_path = os.path.join(self._workspace, os.path.basename(self._module))
        if os.path.exists(module_path):
            self._glob_for_all_of_type(module_path, os.path.join(self.get_output_docs_dir(), module_folder))

        # copy any doc folders
        for src_folder in self._doc_folders:
            if not os.path.abspath(src_folder):
                src_folder = os.path.join(self._workspace, src_folder)
            self._print(f"Copying {src_folder}")
            if not os.path.exists(src_folder):
                raise ValueError(f"Bad path: {src_folder}")
            self._glob_for_all_of_type(src_folder, self.get_output_docs_dir())

        # look for any directory that has both a index and a readme in it- merge them into index.md
        # index = index + readme (index comes first)
        for root, _, files in os.walk(self.get_output_docs_dir()):
            if "index.md" in files and "readme.md" in files:
                with open(os.path.join(root, "index.md"), "a") as index:
                    with open(os.path.join(root, "readme.md"), "r") as readme:
                        lines = readme.readlines()
                        index.write("\n")
                        index.writelines(lines)
                os.remove(os.path.join(root, "readme.md"))

    def _remove_test_documentation(self):
        # if we aren't including any tests
        self._print("Removing test documentation")
        search_paths = [os.path.join("**", "*_test.md"), os.path.join("**", "test_*.md"),
                        os.path.join("**", "test", "*.md")]
        for search_path in search_paths:
            docs = glob.iglob(os.path.join(self.get_output_docs_dir(), search_path), recursive=True)
            for doc in docs:
                os.remove(doc)

    def _nav_generation(self):
        docs_dir = self.get_output_docs_dir()
        search_path = os.path.join(docs_dir, "*.md")
        module_folder = os.path.basename(self._module)

        nav = [
            {
                "Home": "index.md"
            }
        ]
        root_docs = glob.iglob(search_path, recursive=False)
        for doc in root_docs:
            if doc.lower().endswith("index.md"):
                continue
            file_rel_path = os.path.relpath(doc, docs_dir)
            doc_name = self.ConvertToFriendlyName(doc)
            link = {doc_name: file_rel_path}
            nav.append(link)
        # now look at docs from docs folder
        directories = [f for f in os.listdir(docs_dir) if os.path.isdir(os.path.join(docs_dir, f))]
        for directory in directories:
            if directory == module_folder:
                continue
            folder_name = self.ConvertToFriendlyName(directory)
            nav_links = []
            directory_path = os.path.join(docs_dir, directory)
            files = [f for f in os.listdir(directory_path) if f.lower().endswith(".md")]
            for mdfile in files:
                file_path = os.path.join(directory_path, mdfile)
                file_rel_path = os.path.relpath(file_path, docs_dir)
                file_name = self.ConvertToFriendlyName(file_path)
                nav_links.append({file_name: file_rel_path})
            nav.append({folder_name: nav_links})

        # now get auto generated docs from the module
        tree = {}
        search_root = os.path.join(docs_dir, module_folder)
        search_path = os.path.join(search_root, "**", "*.md")
        sub_docs = glob.iglob(search_path, recursive=True)

        for doc in sub_docs:
            doc_name = self.ConvertToFriendlyName(doc)
            doc_relpath = os.path.relpath(doc, search_root)
            doc_path = os.path.join(module_folder, doc_relpath)
            tree_ptr = tree
            path_parts = doc_relpath.split(os.sep)
            if len(path_parts) == 1:
                tree[doc_name] = doc_path
                continue

            for path_part in path_parts:
                path_part_name = self.ConvertToFriendlyName(path_part)
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
        nav.append({"Reference": convert_tree(tree)})  # convert the tree to the mkdocs nav format
        self.set_config("nav", nav)

    def _html(self):
        # write the config to file
        self._write_config()
        mike_mkdocs.build(self.get_output_config_path())

    def deploy(self):
        self._print("Stage: Pre-Deploy")
        self._call_hooks(self.Hooks.PreDeploy)
        self._print("Stage: Deploy")
        # TODO: deploy
        self._print("Stage: Post-Deploy")
        self._call_hooks(self.Hooks.PostDeploy)

    def serve(self, port=3000):
        self._print("Stage: Pre-Serve")
        self._call_hooks(self.Hooks.PreServe)
        self._print("Stage: Serve")
        print("Serving at http://localhost:3000")
        mkdocs_serve("localhost", port, self.get_output_html_dir())
        self._print("Stage: Post-Serve")
        self._call_hooks(self.Hooks.PostServe)
