# Publishing Tianocore Edk2 PyTool Extensions (edk2toolext)

The __edk2toolext__ is published as a pypi (pip) module.  The pip module is
named __edk2-pytool-extensions__.  Pypi allows for easy version management,
dependency management, and sharing.

Publishing/releasing a new version is generally handled thru a server based
build process but for completeness the process is documented here.

## Version Scheme

Versioning follows: aa.bb.cc and is based on tags in git

* aa == Major version.  Changes don’t need to be backward compatible
* bb == Minor version.  Significant new features.  Backward compatibility
  generally maintained except when new feature is used.
* cc == Patch version.  Bug fix or small optional feature.  Backward
  compatibility maintained.

## Github Publishing Process

Note: If this release contains a breaking change, you may need to navigate to
the [Milestones](https://github.com/tianocore/edk2-pytool-extensions/milestones)
page and "edit" the milestone version to roll it to the next minor / major
version. If it was already done, then you don't need to do it again.

1. Navigate to the [Releases](https://github.com/tianocore/edk2-pytool-extensions/releases)
 section on the main page of edk2-pytool-extensions
2. Click `Draft a new release` at the top right of the page
3. Click `Choose a tag` and create the new release version (`v0.21.8`, `v0.22.0`, etc.)
4. Click `Generate release notes`
5. Add a new section `## Dependency Updates`
6. If the major / minor is rolled in this release, add a `## Integration Steps`
   section
7. Move all dependabot contributions to the `## Dependency Updates` section
8. Leave all "true" contributions in the `## What's Changed` section
9. Copy the integration steps from the pull request into the
   `## Integration Steps` section
10. Click `Publish release`

These are the steps you need to do once a release is complete, to setup
contributing to the next tag.

1. Navigate to the [Milestones](https://github.com/tianocore/edk2-pytool-extensions/milestones)
   section on the Pull requests page
2. Click `New Milestone` and create a new tag that should be the last release
   with the patch version + 1
3. Click `Create milestone`
4. Close the old milestone for the latest release tag

NOTE: Feel free to add additional sections to the release notes as necessary.
The release is not immediate. A pipeline will be queued that will perform final
CI checks and then release to pypi. You can monitor this pipeline [HERE](https://dev.azure.com/tianocore/edk2-pytool-extensions/_build?definitionId=10)

## Manual Publishing Process

NOTE: These directions assume you have already configured your workspace for
developing.  If not please first do that.  Directions on the
[developing](developing.md) page.

1. Pass all development tests and checks.
2. Update the __readme.md__ `Release Version History` section with info on all
   important changes for this version.  Remove the "-dev" tag from the version
   about to be released.
3. Get your changes into master branch (official releases should only be done
   from the master branch)
4. Make a git tag for the version that will be released and push tag.  Tag
   format is v\<Major>.\<Minor>.\<Patch>
5. Do the release process

    1. Install tools

        ``` cmd
        pip install --upgrade -e .[publish]
        ```

    2. Build a wheel

        ``` cmd
        python build --sdist --wheel
        ```

    3. Confirm wheel version is aligned with git tag

        ``` cmd
        ConfirmVersionAndTag.py
        ```

    4. Publish the wheel/distribution to pypi

        ``` cmd
        twine upload dist/*
        ```
