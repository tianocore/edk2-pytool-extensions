# @file self_describing_environment.py
# This module contains code that is capable of scanning the source tree for
# files that describe the source and dependencies and acting upon those files.
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##

import os
import logging
from edk2toolext.environment import shell_environment
from edk2toolext.environment import environment_descriptor_files as EDF
from edk2toolext.environment import external_dependency

ENVIRONMENT_BOOTSTRAP_COMPLETE = False
ENV_STATE = None


class self_describing_environment(object):
    def __init__(self, workspace_path, scopes=()):
        super(self_describing_environment, self).__init__()

        self.workspace = workspace_path

        # Determine the final set of scopes.
        # Start with the provided set.
        self.scopes = scopes

        # Validate that all scopes are unique.
        if len(self.scopes) != len(set(self.scopes)):
            raise ValueError(f"All scopes must be unique!\n\t{self.scopes}")

        self.paths = None
        self.extdeps = None
        self.plugins = None

    def _gather_env_files(self, ext_strings, base_path):
        # Make sure that the search extension matches easily.
        search_files = tuple(ext_string.lower() for ext_string in ext_strings)

        # Walk all of the directories under base_path and find all files
        # matching the extension.
        matches = {}
        for root, dirs, files in os.walk(base_path, topdown=True):
            # Check to see whether any of these directories should be skipped.
            # TODO: Allow these to be passed in via arguments.
            for index, dir in enumerate(dirs):
                if dir == '.git':
                    del dirs[index]

            # Check for any files that match the extensions we're looking for.
            for file in files:
                for search_file in search_files:
                    if file.lower().endswith(search_file + ".json") or file.lower().endswith(search_file + ".yaml"):
                        if search_file in matches:
                            matches[search_file].append(
                                os.path.join(root, file))
                        else:
                            matches[search_file] = [os.path.join(root, file)]

        return matches

    def load_workspace(self):
        logging.debug("--- self_describing_environment.load_workspace()")
        logging.debug("Loading workspace: %s" % self.workspace)
        logging.debug("  Including scopes: %s" % ', '.join(self.scopes))

        #
        # First, we need to get all of the files that describe our environment.
        #
        env_files = self._gather_env_files(
            ('path_env', 'ext_dep', 'plug_in'), self.workspace)

        #
        # Now that the files have been found, load them, sort them, and filter them
        # so they can be applied to the environment.
        #
        def _sort_and_filter_descriptors(class_type, file_list, scopes):
            all_descriptors = tuple(class_type(
                desc_file).descriptor_contents for desc_file in file_list)

            known_ids = {}
            active_overrides = {}
            final_list = []

            for scope in scopes:
                for descriptor in all_descriptors:
                    # If this descriptor isn't in the current scope, we can ignore it for now.
                    if descriptor['scope'].lower() != scope.lower():
                        continue

                    cur_file = descriptor['descriptor_file']

                    # If this descriptor has an ID, we need to check for overrides and collisions.
                    if 'id' in descriptor:
                        cur_id = descriptor['id'].lower()

                        # First, check for overrides. There's no reason to process this file if it's being overridden.
                        if cur_id in active_overrides:
                            logging.debug("Descriptor '%s' is being overridden by descriptor '%s' based on ID '%s'." % (
                                cur_file, active_overrides[cur_id], cur_id))
                            continue

                        # Next, check for ID collisions.
                        if cur_id in known_ids:
                            raise RuntimeError(
                                "Descriptor '%s' shares the same ID '%s' with descriptor '%s'." % (
                                    cur_file, cur_id, known_ids[cur_id])
                            )

                        # Finally, we can add this file to the known IDs list.
                        known_ids[cur_id] = cur_file

                    # If we're still processing, we can add this descriptor to the output.
                    logging.debug("Adding descriptor '%s' to the environment with scope '%s'." % (
                        cur_file, scope))
                    final_list.append(descriptor)

                    # Finally, check to see whether this descriptor overrides anything else.
                    if 'override_id' in descriptor:
                        cur_override_id = descriptor['override_id'].lower()
                        # If we're attempting to override someting that's already been processed,
                        # we should spit out a warning of sort.
                        if cur_override_id in known_ids:
                            logging.warning("Descriptor '%s' is trying to override iID '%s', "
                                            "but it's already been processed." %
                                            (cur_file, cur_override_id))
                        active_overrides[cur_override_id] = descriptor['descriptor_file']

            return tuple(final_list)

        if 'path_env' in env_files:
            self.paths = _sort_and_filter_descriptors(
                EDF.PathEnvDescriptor, env_files['path_env'], self.scopes)

        if 'ext_dep' in env_files:
            self.extdeps = _sort_and_filter_descriptors(
                EDF.ExternDepDescriptor, env_files['ext_dep'], self.scopes)

        if 'plug_in' in env_files:
            self.plugins = _sort_and_filter_descriptors(
                EDF.PluginDescriptor, env_files['plug_in'], self.scopes)

        return self

    # This is a generator to reduce code duplication when wrapping the pathenv objects.
    def _get_paths(self):
        if self.paths is not None:
            # Apply in reverse order to get the expected hierarchy.
            for path_descriptor in reversed(self.paths):
                # Use the helper factory to get an object
                # capable of managing each dependency.
                yield EDF.PathEnv(path_descriptor)

    # This is a generator to reduce code duplication when wrapping the extdep objects.
    def _get_extdeps(self):
        if self.extdeps is not None:
            # Apply in reverse order to get the expected hierarchy.
            for extdep_descriptor in reversed(self.extdeps):
                # Use the helper factory to get an object
                # capable of managing each dependency.
                yield external_dependency.ExtDepFactory(extdep_descriptor)

    def _apply_descriptor_object_to_env(self, desc_object, env_object):
        # Walk through each possible environment modification
        # and apply to the environment as required.

        if 'set_path' in desc_object.flags:
            env_object.insert_path(desc_object.published_path)
        if 'set_pypath' in desc_object.flags:
            env_object.insert_pypath(desc_object.published_path)
        if 'set_build_var' in desc_object.flags:
            env_object.set_build_var(
                desc_object.var_name, desc_object.published_path)
        if 'set_shell_var' in desc_object.flags:
            env_object.set_shell_var(
                desc_object.var_name, desc_object.published_path)

    def update_simple_paths(self, env_object):
        logging.debug("--- self_describing_environment.update_simple_paths()")
        for path in self._get_paths():
            self._apply_descriptor_object_to_env(path, env_object)

    def update_extdep_paths(self, env_object):
        logging.debug("--- self_describing_environment.update_extdep_paths()")
        for extdep in self._get_extdeps():
            self._apply_descriptor_object_to_env(extdep, env_object)

    def update_extdeps(self, env_object):
        logging.debug("--- self_describing_environment.update_extdeps()")
        for extdep in self._get_extdeps():
            # Check to see whether it's necessary to fetch the files.
            if not extdep.verify():
                # Get rid of extdep's published path since it could get changed
                # during the fetch routine.
                if 'set_path' in extdep.flags:
                    env_object.remove_path_element(extdep.published_path)
                if 'set_pypath' in extdep.flags:
                    env_object.remove_pypath_element(extdep.published_path)
                extdep.clean()
                extdep.fetch()
                # Re-apply the extdep to environment
                self._apply_descriptor_object_to_env(extdep, env_object)

    def clean_extdeps(self, env_object):
        for extdep in self._get_extdeps():
            extdep.clean()
            # TODO: Determine whether we want to update the env.

    def verify_extdeps(self, env_object):
        result = True
        for extdep in self._get_extdeps():
            if not extdep.verify():
                result = False
                logging.error("Dependency '%s' is not met!" % extdep.name)

        return result


def DestroyEnvironment():
    ''' Destroys global envirornment state '''
    global ENVIRONMENT_BOOTSTRAP_COMPLETE, ENV_STATE

    ENVIRONMENT_BOOTSTRAP_COMPLETE = False
    ENV_STATE = None


def BootstrapEnvironment(workspace, scopes=()):
    global ENVIRONMENT_BOOTSTRAP_COMPLETE, ENV_STATE

    if not ENVIRONMENT_BOOTSTRAP_COMPLETE:
        #
        # ENVIRONMENT BOOTSTRAP STAGE 1
        # Locate and load all environment description files.
        #
        build_env = self_describing_environment(
            workspace, scopes).load_workspace()

        #
        # ENVIRONMENT BOOTSTRAP STAGE 2
        # Parse all of the PATH-related descriptor files to make sure that
        # any required tools or Python modules are now available.
        #
        shell_env = shell_environment.GetEnvironment()
        build_env.update_simple_paths(shell_env)

        #
        # ENVIRONMENT BOOTSTRAP STAGE 3
        # Now that the preliminary paths have been loaded,
        # we can load the modules that had greater dependencies.
        #
        build_env.update_extdep_paths(shell_env)

        # Debug the environment that was produced.
        shell_env.log_environment()

        ENVIRONMENT_BOOTSTRAP_COMPLETE = True
        ENV_STATE = (build_env, shell_env)

    # Return the environment as it's configured.
    return ENV_STATE


def CleanEnvironment(workspace, scopes=()):
    # Bootstrap the environment.
    (build_env, shell_env) = BootstrapEnvironment(workspace, scopes)

    # Clean all the dependencies.
    build_env.clean_extdeps(shell_env)


def UpdateDependencies(workspace, scopes=()):
    # Bootstrap the environment.
    (build_env, shell_env) = BootstrapEnvironment(workspace, scopes)

    # Clean all the dependencies.
    build_env.update_extdeps(shell_env)


def VerifyEnvironment(workspace, scopes=()):
    # Bootstrap the environment.
    (build_env, shell_env) = BootstrapEnvironment(workspace, scopes)

    # Clean all the dependencies.
    return build_env.verify_extdeps(shell_env)
