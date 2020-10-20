# Making a new Plugin Type

Any file that ends in `_plug_in` is automatically included in the list of plugins.
The only thing you need to do is to create a class and use it.

You once you have a plugin manager set up:

```python
self.plugin_manager = plugin_manager.PluginManager()
failedPlugins = self.plugin_manager.SetListOfEnvironmentDescriptors(
    build_env.plugins)
```

All you need to do is find and run your plugin.

```python
# Get list of descriptors for ICiBuildPlugin type objects
pluginList = self.plugin_manager.GetPluginsOfClass(plugin_manager.ICiBuildPlugin)
# Descriptor.Obj is going to be a callable object of type ICiBuildPlugin
for Descriptor in pluginList:
    rc = Descriptor.Obj.RunBuildPlugin(...)
```

Since you are creating and using a new plugin type, you can define the API to be whatever you want!
