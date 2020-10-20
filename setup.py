## @file setup.py
# This contains setup info for edk2-pytool-extensions pip module
#
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
import setuptools
from setuptools.command.sdist import sdist
from setuptools.command.install import install
from setuptools.command.develop import develop
from edk2toolext.bin.nuget import DownloadNuget

with open("readme.md", "r") as fh:
    long_description = fh.read()


class PostSdistCommand(sdist):
    """Post-sdist."""
    def run(self):
        # we need to download nuget so throw the exception if we don't get it
        DownloadNuget()
        sdist.run(self)


class PostInstallCommand(install):
    """Post-install."""
    def run(self):
        try:
            DownloadNuget()
        except:
            pass
        install.run(self)


class PostDevCommand(develop):
    """Post-develop."""
    def run(self):
        try:
            DownloadNuget()
        except:
            pass
        develop.run(self)


setuptools.setup(
    name="edk2-pytool-extensions",
    author="Tianocore Edk2-PyTool-Extensions team",
    author_email="sean.brogan@microsoft.com",
    description="Python tools supporting UEFI EDK2 firmware development",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/tianocore/edk2-pytool-extensions",
    license='BSD-2-Clause-Patent',
    packages=setuptools.find_packages(),
    use_scm_version=True,
    setup_requires=['setuptools_scm'],
    cmdclass={
        'sdist': PostSdistCommand,
        'install': PostInstallCommand,
        'develop': PostDevCommand,
    },
    include_package_data=True,
    entry_points={
        'console_scripts': ['stuart_setup=edk2toolext.invocables.edk2_setup:main',
                            'stuart_update=edk2toolext.invocables.edk2_update:main',
                            'stuart_build=edk2toolext.invocables.edk2_platform_build:main',
                            'stuart_ci_build=edk2toolext.invocables.edk2_ci_build:main',
                            'stuart_ci_setup=edk2toolext.invocables.edk2_ci_setup:main',
                            'stuart_pr_eval=edk2toolext.invocables.edk2_pr_eval:main',
                            'omnicache=edk2toolext.omnicache:main',
                            'nuget-publish=edk2toolext.nuget_publishing:go',
                            'sig_db_tool=edk2toolext.uefi.sig_db_tool:main',
                            'firmware_policy_tool=edk2toolext.windows.policy.firmware_policy_tool:main',
                            'edk2_capsule_tool=edk2toolext.capsule.capsule_tool:main',
                            'versioninfo_tool=edk2toolext.versioninfo.versioninfo_tool:main']
    },
    install_requires=[
        'pyyaml>=5.2',
        'edk2-pytool-library>=0.10.13',
        'pefile>=2019.4.18'
    ],
    extras_require={
        'openssl': ['pyopenssl']
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers"
    ]
)
