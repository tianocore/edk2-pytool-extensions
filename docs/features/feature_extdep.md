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

`__init__` sets up all the required fields from the descriptor object. If you are adding a field to the descriptor,
just make sure to call `super().__init__(descriptor)`

#### clean

Clean will call `shutil.rmtree(dir_path)` twice and then give up.

#### verify

Verify is meant to return true if the state_file.json matches the ext_dep.json file.

## 2) Add your type to ExtDepFactory in edk2toolext.environment.external_dependency

Adding your type here will be necessary in order for the ExtDepFactory to recognize your new type as valid.
