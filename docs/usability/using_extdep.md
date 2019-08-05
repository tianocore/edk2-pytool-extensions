# External Dependencies

## Overview

External dependencies are a way within the build environment to describe external dependencies and have Stuart fetch them when doing the *stuart_update* operation.  Stuart will also verify the ext_dep state when doing a build to ensure the environment is in the required state prior to building.

Ext_deps have solved three major issues.

1. Binaries causing bloat of git repositories
2. Conditional inclusion of a dependency (only for certain usages)
3. Reproducability and tracking of dependencies

## Why

### Git Bloat

Best practices advise against checking in binaries to git repositories as the overall size of git repos will balloon quickly causing slow clones and slow operations.  Building firmware often requires custom tools, firmware blobs, or other binaries and it is critical these are maintained and versioned with the repository.  Package management tools can solve the hosting of these binaries but edk2 has no built in tool to track them, extract them, etc.  Ext_deps provide that mechanism.

### Conditional Inclusion (scopes)

Ext_deps leverage the environment scope concept so that a repository can carry ext_deps that are only used in some conditions.  Scopes are a string that a environment envoking tool uses to indicate what ext_deps should be used.  These scopes are loosly based on functionality.

### Reproducability and Tracking

Ext_deps are common infrastructure so that all external dependencies can be handled consistantly.  Versions are added to the version report so that for any given operation (like build) a complete list of what was used is available.  This makes tracking versions consistant and "free".  Ext_deps when fetched will update their state.  If the repository is updated to include a new ext_dep version the tool will be told the environment state is not valid and can then enforce thet user updates their environment.

## Examples of Usage
Here are a few examples where ext_deps have been found useful:

* An ext_dep describing a test repository that is only needed when running unit tests.  By leveraging scopes this ext_dep is only fetched when the unittest scope is active.
* Similiar to the unit test dependency, support for CI builds often require unique dependencies.  When doing a CI build of a core repository it might have critical dependencies that need to be fetched but when the core repository is included within a platform repository as a dependency, then the core would defer to the platform as to how to include the dependency.
* An ext_dep describing the compiler toolchain.  This ext_dep is only needed when a builder is using that toolchain for that target type.
* An ext_dep describing some platform binary.  This is only needed when building that given platform and since git is not optiized to handle binaries this saves a lot of unnecessary bloat in the repository.

## Supported Types

### NuGet Dependency

Nuget dependency is used to fetch files from a nuget feed.  This feed can be either unauthenticated or authenticated.  Support is done by using the nuget command line tool.  When the ext_dep type is set to ***nuget*** the descriptor will be intrepreted as a nuget dependency.  Nuget has a few nice features such as caching, authentication, versioning, and is platform and language agnostic.

### Web Dependency

Web dependency is used to describe a dependency on an asset that can be downloaded via a URL and a web request.  It will download whatever is located at the source URL and can support single files, compressed files, and folders.  
When the ext_dep type is set to ***web*** the ext_dep will be intrepreted as a web dependency.

### Git Dependency

Git dependency is used to describe a dependency on a git repository.  This repository will be cloned to the ext_dep location and the version will be checked out.  For this ext_dep descriptor the type is ***git***.  A git dependency should be treated as read-only because the verify and clean phase will do destructive operations where local changes would be destroyed.

### Developer Note

To create a new Dependency type it requires a new subclass of the `ExternalDependency` class.  The subclass needs to have a type field and then factory method in `ExternalDependency.py` needs to be updated to create new instances of the new type.

## How they work

Ext_deps are found by the SDE (self-describing environment). If you have any questions about that, go review the document for that. Once the ext_dep is found it can be interacted with depending on use case/tool. Objects created with the data from ext_dep descriptors and are subclassed according to the "type" field in the descriptor. 

These objects contain the code for fetching, validating, updating, and cleaning dependency objects and metadata. When referenced from the SDE itself, they can also update paths and other build/shell vars in the build environment.

## How to create/use an ext_dep

An ext_dep is defined by a json file that ends in _ext_dep.json
It must follow the schema outlined below. It will be unpacked in a new folder in the same directory as the .json file in a folder named {name}_extdep.

We strongly recommend adding any folder that ends in _extdep to your repositories gitignore. It would look like this:

```.gitignore
*_extdep/
```

Ext_Dep Example json file

```json
{
"scope": "cibuild",
"type": "nuget",
"name": "iasl",
"source": "https://api.nuget.org/v3/index.json",
"version": "20190215.0.0",
"flags": ["set_path", "host_specific"]
}
```

## The base schema

### Required

 scope: (required) (string) - name of scope when this ext_dep should be evaluated
- type: (required) (string from list of known types) - See above for types
- name: This is the name of the ext_dep and will be part of the path where the ext_dep is unpacked
- source: see per type
- version: see per type
- flags: Optional conditions that can be applied. Can be empty list

### Optional

- id: (string) - Identifier allowing override feature - Must be unique
- override_id: (string) - Identifier of the ext_dep this should replace (allows for changing an ext_dep in another source by id)
- var_name: TODO

### Nuget Type Schema differences

- source: This should be the nuget feed URL
- version: nuget version.  Generally xx.yy.zz

For this type there are zero additional ext_dep fields.

### Web Type Schema differences

- source: url to download
- version: only used for folder naming

For this type there are three additional ext_dep fields:

1. internal_path (required)
    ```
    This describes the internal structure of whatever we are downloading.

    If you are just downloading a file, include the name you would like the file to be.

    If you are downloading a directory, indicate so with a / before the path. The folder the path points to will have it's contents copied into the final name_ext_dep folder.
    ```

2. compression_type (optional)
    ```
    Including this field is indicating that the file being downloaded is compressed and that you would like the contents of internal_path to be extracted. If you have a compressed file and would not like it to be decompressed, omit this field.

    Currently tar and zip files are supported. If the file is not compressed, omit this field.
    ```

3. sha256 (optional)
    ```
    If desired, you can provide the hash of your file. This hash will be checked against what is being downloaded to ensure it is valid. It is strongly recommended to use this to ensure the contents are as expected.
    ```

### Git Type Schema Differences

- source: url of git repo
- version: commit hash to checkout

#### Experimental Option: url_creds_var

If this field is found in the descriptor file when initializing this extdep, the string value listed will be checked against the environment's shell_vars. If a matching var is found, this string in the shell_var will be prepended to the URL host for the source URL.

NOTE: This is intended for server builds and may be subject to change as we figure out how it fits into build flows. Also note that any creds passed may end up in build logs and other server-side artifacts. Use with caution!

Example:
```py
TEST_DESCRIPTOR = {
        "scope": "global",
        "type": "git",
        "name": "ExampleRepo",
        "source": "http://example.com/path/to/repo.git",
        "version": "7fd1a60b01f91b314f59955a4e4d4e80d8edf11d",
        "url_creds_var": 'my_url_creds'
        "flags": []
    }

# Populate shell var.
env.set_shell_var('my_url_creds', 'my_user:my_pass')

# URL cloned by the GitDependency object will look like...
final_url = 'http://my_user:my_pass@example.com/path/to/repo.git'
```

## The Flags

There are specific flags that do different things. Flags are defined by MuEnviroment and cannot be modified without updating the pip module. More information on the flags can be found in the SDE documentation.