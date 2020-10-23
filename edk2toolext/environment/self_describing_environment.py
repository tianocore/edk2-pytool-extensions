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
from multiprocessing import dummy
import time


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

        # First, we need to get all of the files that describe our environment.
        env_files = self._gather_env_files(('path_env', 'ext_dep', 'plug_in'), self.workspace)

        # Next, get a list of all our scopes
        all_scopes_lower = [x.lower() for x in self.scopes]

        # Now that the files have been found, load them, sort them, and filter them
        # so they can be applied to the environment.

        # We need to convert them from files to descriptors
        all_descriptors = list()

        # helper function to get all the descriptors of a type and cast them
        def _get_all_descriptors_of_type(key, class_type):
            if key not in env_files:
                return tuple()
            return tuple(class_type(desc_file) for desc_file in env_files[key])

        # Collect all the descriptors of each type
        all_descriptors.extend(_get_all_descriptors_of_type('path_env', EDF.PathEnvDescriptor))
        all_descriptors.extend(_get_all_descriptors_of_type('ext_dep', EDF.ExternDepDescriptor))
        all_descriptors.extend(_get_all_descriptors_of_type('plug_in', EDF.PluginDescriptor))

        # Get the properly scoped descriptors by checking if the scope is in the list of all the scopes
        scoped_desc_gen = [x for x in all_descriptors if x.descriptor_contents['scope'].lower() in all_scopes_lower]
        scoped_descriptors = list(scoped_desc_gen)

        # Check that each found item has a unique ID, that's an error if it isn't
        allids_gen = [x.descriptor_contents['id'].lower() for x in scoped_descriptors if 'id' in x.descriptor_contents]
        all_ids = list(allids_gen)
        all_unique_ids = set(all_ids)
        if len(all_ids) != len(all_unique_ids):
            logging.error("Multiple descriptor files share the same id")
            all_unique_id_dict = {}
            for desc_id in all_ids:
                dict_id_seen = desc_id not in all_unique_id_dict
                all_unique_id_dict[desc_id] = 1 if dict_id_seen else all_unique_id_dict[desc_id] + 1
            for desc_id in all_unique_id_dict:
                if all_unique_id_dict[desc_id] == 1:
                    continue
                # get the descriptors
                desc_of_id = [x for x in scoped_descriptors if x.descriptor_contents['id'].lower() == desc_id]
                paths_of_desc_of_id = [x.file_path for x in desc_of_id]
                invalid_desc_paths = f"{os.pathsep} ".join(paths_of_desc_of_id)
                logging.error(f"Descriptors that have this id {desc_id}: {invalid_desc_paths}")
            raise RuntimeError("Multiple descriptor files share the same id")

        # Now check for overrides, first get a list of all the descriptors that have an override id tag
        override_descriptors = [x for x in scoped_descriptors if "override_id" in x.descriptor_contents]
        active_overrides = {}
        for desc in override_descriptors:
            override_id = desc.descriptor_contents["override_id"].lower()
            # we found this was already overriden, make sure to let the user know
            if override_id in active_overrides:
                logging.warning("A descriptor file is trying to override a file that was previously overriden")
                logging.warning(f"File ID being overriden: {override_id}")
                logging.warning(f"Previous override: {active_overrides[override_id].file_path}")
                logging.warning(f"New override: {desc.file_path}")
                raise RuntimeError(f"Multiple descriptor files share the same override_id: {override_id}")
            active_overrides[override_id] = desc

        # Now we filter the overriden id's out and debug to the user whether we are including them or not
        overriden_ids = active_overrides.keys()
        final_descriptors = []
        for desc in scoped_descriptors:
            desc_file = desc.file_path
            if 'id' in desc.descriptor_contents:
                desc_id = desc.descriptor_contents['id'].lower()
                if desc_id in overriden_ids:
                    override = active_overrides[desc_id]
                    desc_name = f"{desc_file}:{desc_id}"
                    override_name = f"{override.file_path}"
                    logging.debug(f"Skipping descriptor {desc_name} as it is being overridden by {override_name}.")
                    continue
            # add them to the final list
            desc_scope = desc.descriptor_contents['scope']
            logging.debug(f"Adding descriptor {desc_file} to the environment with scope {desc_scope}")
            final_descriptors.append(desc)

        # Finally, sort them back in the right categories
        self.paths = list([x.descriptor_contents for x in final_descriptors if isinstance(x, EDF.PathEnvDescriptor)])
        self.extdeps = list(
            [x.descriptor_contents for x in final_descriptors if isinstance(x, EDF.ExternDepDescriptor)])
        self.plugins = list([x.descriptor_contents for x in final_descriptors if isinstance(x, EDF.PluginDescriptor)])

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

    def report_extdep_version(self, env_object):
        logging.debug("--- self_describing_environment.report_extdep_version()")
        for extdep in self._get_extdeps():
            extdep.report_version()

    def update_extdeps(self, env_object):
        logging.debug("--- self_describing_environment.update_extdeps()")
        # This function is called by our thread pool

        def update_extdep(self, extdep):
            # Check to see whether it's necessary to fetch the files.
            try:
                if not extdep.verify():
                    # Get rid of extdep published path since it could get changed
                    # during the fetch routine.
                    if 'set_path' in extdep.flags:
                        env_object.remove_path_element(extdep.published_path)
                    if 'set_pypath' in extdep.flags:
                        env_object.remove_pypath_element(extdep.published_path)
                    extdep.clean()
                    extdep.fetch()
                    # Re-apply the extdep to environment
                    self._apply_descriptor_object_to_env(extdep, env_object)
                return True
            except RuntimeError as e:
                logging.warning(f"[SDE] Failed to fetch {extdep}: {e}")
                if extdep.error_msg is not None:
                    logging.warning(extdep.error_msg)
                return False
            except FileNotFoundError:
                logging.warning(f"[SDE] Unable to fetch {extdep}")
                if extdep.error_msg is not None:
                    logging.warning(extdep.error_msg)
                return False
        # prep the worker pool
        all_extdeps = self._get_extdeps()
        self_extdeps = [(self, x) for x in all_extdeps]
        num_extdeps = len(self_extdeps)
        # if there are no ext_deps to update, bail early
        if num_extdeps == 0:
            return (0, 0)
        # don't create more threads than needed
        num_threads = min(os.cpu_count(), num_extdeps)
        # create a pool
        pool = dummy.Pool(num_threads)
        logging.debug(f"Creating {num_threads} threads for the SDE update")
        # map the task to the data
        pool_handle = pool.starmap_async(update_extdep, self_extdeps)
        pool.close()
        # use print so it doesn't go to the log
        print("Updating", end="", flush=True)
        old_count = num_extdeps
        # wait for the pool_handle (MapResult) to finish
        while pool_handle._number_left != 0:
            while(old_count != pool_handle._number_left and old_count > 0):
                print(".", end="", flush=True)
                old_count -= 1
            time.sleep(0.1)  # wait 100 ms
        print(". Done")
        # get the results
        results = pool_handle.get()
        success_count = results.count(True)
        failure_count = results.count(False)
        exception_count = results.count(None)
        if len(results) != num_extdeps or exception_count > 0:
            # We don't know where the error since we don't get a return result from it
            # so just tell users to check their logs
            raise RuntimeError("We encountered an exception while updating ext-deps. Review your log")
        return success_count, failure_count

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
    ''' Destroys global environment state '''
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

        #
        # ENVIRONMENT BOOTSTRAP STAGE 4
        # Report versions into the version aggregator
        build_env.report_extdep_version(shell_env)

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
    return build_env.update_extdeps(shell_env)


def VerifyEnvironment(workspace, scopes=()):
    # Bootstrap the environment.
    (build_env, shell_env) = BootstrapEnvironment(workspace, scopes)

    # Clean all the dependencies.
    return build_env.verify_extdeps(shell_env)
