# Developing Tianocore Edk2 PyTool Extensions (edk2toolext)

## Pre-Requisites

1. Get the code

    ``` cmd
    git clone https://github.com/tianocore/edk2-pytool-extensions.git
    ```

2. Install development dependencies

    ``` cmd
    pip install --upgrade -r requirements.txt
    ```

3. Uninstall any copy of edk2-pytool-extensions

    ``` cmd
    pip uninstall edk2-pytool-extensions
    ```

4. Install from local source (run command from root of repo)

    ``` cmd
    pip install -e .
    ```

## Testing

1. Run a Basic Syntax/Lint Check (using flake8) and resolve any issues

    ``` cmd
    flake8 edk2toolext
    ```

    INFO: Newer editors are very helpful in resolving source formatting errors (whitespace, indentation, etc). In VSCode open the py file and use ++alt+shift+f++ to auto format.  

2. Run the `BasicDevTests.py` script to check file encoding, file naming, etc

    ```cmd
    BasicDevTests.py
    ```

3. Run pytest with coverage data collected

    ``` cmd
    pytest -v --junitxml=test.junit.xml --html=pytest_report.html --self-contained-html --cov=edk2toolext --cov-report html:cov_html --cov-report xml:cov.xml --cov-config .coveragerc
    ```

4. Look at the reports
    * pytest_report.html
    * cov_html/index.html

## Conventions Shortlist

### File and folder names

Use python defined Pep conventions.  For example package, module, and class naming should follow PEP8 (https://www.python.org/dev/peps/pep-0008/)

### Comments

Docstring style comments should be added to each public function and class.  \*Existing code should be updated to be compliant as it is modified.  

### New Module or Class

When creating a new module or class it should be clearly defined for a single purpose and provide general purpose support.

The module should be added to the package in which the interface is defined.

* For example for modules supporting interfaces defined in the UEFI specification it would be in the __uefi__ package.  
* If it is defined by EDK2 then it should be in the __uefi.edk2__ package.

Documentation of the feature should be added to the __docs/features__ folder in markdown format.  The filename should be the package import path.  For example for _edk2toolext.pkg1.mod1.py_ module the filename for documentation would be `pkg1.mod1.md`.  The content of this documentation should be focused on why.  Docstrings within the module should describe functional parameters and usage info.

Unit tests should be written in python unittest or pytest format.  A test module should be added __test__ folder.  The filename should be `test_module.py`.
