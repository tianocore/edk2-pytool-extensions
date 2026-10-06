# Plugin Manager

The plugin manager is the internal service that loads plugins discovered by
the [Self Describing Environment](/features/sde.md). Platform repositories
normally do not construct or dispatch the plugin manager themselves; Stuart
invocables do that work.

For an end-to-end authoring guide with complete descriptors, Python modules,
configuration, and usage examples, see
[Creating Plugins in a Platform Repository](/features/creating_plugins.md).

## Plugin types

Plugin type is determined by the interface implemented by the loaded class.

### UefiBuildPlugin

`IUefiBuildPlugin` provides `do_pre_build()` and `do_post_build()` callbacks
for `stuart_build`. Pre-build callbacks run after `PlatformPreBuild()`.
Post-build callbacks run after the firmware build and `PlatformPostBuild()`.
Plugin ordering is not guaranteed.

### UefiHelperPlugin

`IUefiHelperPlugin` registers functions on a shared helper object. Build code
can call registered helpers through `UefiBuilder.Helper`, and CI build plugins
receive the same helper object as their `PLMHelper` argument.

### CiBuildPlugin

`ICiBuildPlugin` represents a CI task or test. `stuart_ci_build` runs active CI
plugins for each selected package and applicable target, records their results
in the JUnit report, and passes each plugin its merged repository and package
configuration.

### DscProcessorPlugin

`IDscProcessorPlugin` is an experimental interface for transforming the active
DSC. It is not currently enabled in the standard build flow.

## How loading works

1. The Self Describing Environment scans the workspace for plugin descriptor
   files.
2. It filters descriptors to the active scopes supplied by the settings
   manager.
3. The plugin manager imports the descriptor's module, constructs its named
   class, and groups the instance by its implemented interface.
4. The active invocable requests and dispatches the relevant plugin type.
   Helper plugins are dispatched during initialization so they can register
   their functions.

The standard plugin types are dispatched by Stuart. Custom invocables can use
the plugin manager directly when they intentionally define a new plugin
contract, but platform build and CI plugins should use the standard
interfaces.

## Disabling plugins

Set `<ModuleName>=skip` before plugin loading to disable an individual plugin.
For CI-specific filtering, including package-level `skip: true` and
`--disable-all`, see [Continuous Integration with Stuart](/using/ci.md#faq).
