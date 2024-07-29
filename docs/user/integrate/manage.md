# Managing a Codebase

The idea here is that you have code and you have a to-do list of tasks to do.
Maybe you want to make sure all the drivers compile, maybe you want to check all
the images in your file tree and make sure they are encoded correctly.

These use cases will fit into our 'CI' tools category.

## Getting Started

Our CI tools simplify the process of creating and running
[CiBuildPlugins](/features/plugin_manager.md) on packages within any
repository, not just a platform repository. We even provide a simple means to
filter which packages are tested based off which files have been changed
through `edk2_pr_eval.py`/`stuart_pr_eval.exe`. These packages do not need to
be tied to a platform either; they can be in the platform repository or in a
separate repository. Some examples of `CiBuildPlugins` are uncrustify audits,
guid audits, package builds, etc.

`stuart_ci_setup` can be called to clone whatever code repositories would be
required for this operation. `stuart_update` can be called to download all the
tools the environment says it needs. From there, `stuart_ci_build` takes a list of
packages to look at and runs all plugins on each package.

Similar to [Build a Platform](/integrate/build.md), this process involves invocables.
Since we already explained the process of creating a settings file to provide
platform information to the build invocables, we wont go into to much detail
here. Just know that you have additional invocables that you will need override
to make the CI invocables work!

!!! Tip
    Create a separate CI Settings file for codebase management not directly related to the platform!

Take a look all all the relevant invocables below:

- [Edk2InvocableSettingsInterface](/api/edk2_invocable.md#edk2toolext.edk2_invocable.Edk2InvocableSettingsInterface)
- [MultiPkgAwareSettingsInterface](/api/invocables/edk2_multipkg_aware_invocable.md#edk2toolext.invocables.edk2_multipkg_aware_invocable.MultiPkgAwareSettingsInterface)
- [CiSetupSettingsManager](/api/invocables/edk2_ci_setup.md#edk2toolext.invocables.edk2_ci_setup.CiSetupSettingsManager)
- [UpdateSettingsManager](/api/invocables/edk2_update.md#edk2toolext.invocables.edk2_update.UpdateSettingsManager)
- [CiBuildSettingsManager](/api/invocables/edk2_ci_setup.md#edk2toolext.invocables.edk2_ci_setup.CiSetupSettingsManager)
- [PrEvalSettingsManager](/api/invocables/edk2_pr_eval.md#edk2toolext.invocables.edk2_pr_eval.PrEvalSettingsManager)
