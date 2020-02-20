# Making a new Ext Dep Type

This will require a core code change in order to work! Please contact the maintainers to facilitate this process.

## 1) Make a new class

This class needs to implement a few things...

### Required Functions

These functions are *not* implemented by the base class.

#### fetch

### Optional Functions

These functions *are* implemented by the base class but you could overload them to add more functionality.
I will describe the action of the base class here.\

#### __init__

`__init__` sets up all the required fields from the descriptor object. If you are adding a field to the descriptor, just make sure to call `super().__init__(descriptor)`

#### clean

Clean will call `shutil.rmtree(dir_path)` twice and then give up.

#### verify

Verify is meant to return true if the state_file.json matches the ext_dep.json file.

The base type for external dependencies has provisions for the concept of a local version.
By specifying `LOCAL` as the version in the json file, the SDE will not consider it a failure.
This can be useful for testing repos where you don't have access to the nuget feed or github repo, but still want to build.
By creating the correct folder, and placing the json file in there, you can force the system to allow you through.
You will get a warning in your build log that you're entering some scary waters.

## 2) Add your type to ExtDepFactory in edk2toolext.environment.external_dependency

Adding your type here will be necessary in order for the ExtDepFactory to recognize your new type as valid.