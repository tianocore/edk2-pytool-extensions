# Developing Tianocore Edk2 PyTool Extensions (edk2toolext)

There are a lot of parts of pytools. Here's a helpful diagram to help you sort
out all the different parts.

![Picture that shows the parts of pytools](pytools.png)

## Pre-Requisites

* Make sure you have python 3.11.x or newer available on path
* Make sure you have git installed and available on path

1. Get the code

    ``` cmd
    git clone https://github.com/tianocore/edk2-pytool-extensions.git
    ```

2. __Strongly Recommended__ Create a Python virtual environment
   1. open cmd prompt

   2. Navigate to parent folder of where you cloned
      * NOTE: this is where I like to create my virtual environments.  You can
        organize these however you like but you will want to launch this virtual
        environment each time you want to work on or test pytools.

   3. run `python -m venv pytool-ext-venv` to make your virtual environment.  In
      this case `pytool-ext-venv` is the name of the virtual environment and
      folder that will be created.  You can name it whatever works for you.

   4. Activate the virtual environment for this session

      ```cmd
      pytool-ext-venv\Scripts\activate
      ```

   5. Your shell prompt should now indicate you are in a virtual environment.

   6. change working directory to the root of the cloned repository.

3. Install development dependencies into this virtual environment

    ``` cmd
    pip install --upgrade -e .[dev,docs]
    ```

4. To support spell checking / validation NodeJs and cspell are used.

    * Install NodeJS from <https://nodejs.org/en/>
    * Use npm to install cspell.

      ```cmd
      npm install -g cspell
      ```

    * Src and doc available:
      * <https://github.com/streetsidesoftware/cspell>
      * <https://www.npmjs.com/package/cspell>

5. To support linting the markdown files NodeJs and markdownlint are used.

    * Install NodeJS from <https://nodejs.org/en/>
    * Use npm to install markdownlint-cli.

      ```cmd
      npm install -g markdownlint-cli
      ```

    * Src and doc available:
      * <https://www.npmjs.com/package/markdownlint>
      * <https://www.npmjs.com/package/markdownlint-cli>

## Testing

PIP modules used in this section such as `ruff` and `pydocstyle` are installed when you run `pip install -e .[dev]`
as described below.

> See [`pyproject.toml`](../../pyproject.toml) for the full list of development dependencies

1. Run a Basic Syntax/Lint Check (using ruff) and resolve any issues

    * Run ruff

    ``` cmd
    ruff check .
    ruff format --check
    ```

    * Note: Newer editors are very helpful in resolving source formatting errors. For example, in VSCode, you can
            open the Python file and use `Alt+Shift+F` to auto format. See the [Ruff VSCode extension](https://marketplace.visualstudio.com/items?itemName=charliermarsh.ruff)
            for more information.

    * Note: `ruff` is a wrapper around tools like `pydocstyle`. See [`pyproject.toml`](../../pyproject.toml) for
            more details.

2. Run the `BasicDevTests.py` script to check file encoding, file naming, etc

    ```cmd
    BasicDevTests.py
    ```

3. Run Coverage with pytest test execution

    ``` cmd
    coverage run -m pytest
    ```

    INFO: If you only want to test a single file you can supply that path at the
    end and then only that module will be run.

    Coverage is uploaded to `codecov.io`. For more information, review
    `coverage.md` in the docs folder.

4. Generate and review the html report

    You can one run or the other.

    ``` cmd
    coverage report
    coverage html
    ```

5. Run the spell checker

    ```cmd
    cspell -c .cspell.json "**/*.py" "**/*.md"
    ```

6. Run the markdown linter

    ```cmd
    markdownlint "**/*.md"
    ```

7. Run mkdocs build
   * Fix warnings and errors

    ```cmd
    mkdocs build --strict
    ```

### Githooks

Optionally, there are two githooks provided to automate testing locally before running CI

* githooks/basic-pre-commit-config.yaml
  * This file runs only the quickest checks in order to test the code for common mistakes
  * This yaml will pull in all the tools into an enviornment it needs to run
* githooks/advanced-pre-commit-config.yaml
  * This file will run all the basic checks and the longer running checks
  * This yaml will need mkdocs installed prior to running

#### Installing

Installing is entirely optional, a developer may choose to run this manually.
The following command will enable this pre-commit to prior to each commit. If it detects
issues it will fail to commit until they are fixed.

```bash
pip install pre-commit
pre-commit install -c githooks/basic-pre-commit-config.yaml
```

#### Running across the entire repository (Manually)

This step is entirely manual but gives a good example of what the behavior of this tool will be.

```bash
pre-commit run --all-files -c githooks/basic-pre-commit-config.yaml
```

#### Uninstalling

```bash
pre-commit uninstall
```

## Conventions Shortlist

### File and folder names

Use python defined Pep conventions.  For example package, module, and class
naming should follow PEP8 (<https://www.python.org/dev/peps/pep-0008/>)

### Comments

Docstring style comments should be added to each public function and class.
\*Existing code should be updated to be compliant as it is modified.

### New Module or Class

When creating a new module or class it should be clearly defined for a single
purpose and provide general purpose support.

Documentation of the feature should be added to the __docs/features__ folder in
markdown format.  The filename should be the package import path.  For example
for _edk2toolext.pkg1.mod1.py_ module the filename for documentation would be
`pkg1.mod1.md`.  The content of this documentation should be focused on why.
Docstrings within the module should describe functional parameters and usage
info.

Unit tests should be written in python unittest or pytest format.  A test module
should be added __test__ folder.  The filename should be `test_module.py`.

### Spell Checking / False Positives

The cspell dictionary is not perfect and there are cases where technical words
or acronyms are not found in the dictionary.  There are two ways to resolve
false positives and the choice for which method should be based on how broadly
the word should be accepted.

#### CSpell Base Config file

If the change should apply to all files in repository code and documentation
then it should be added to the base config file (__.cspell.json__) `words`
section.  This is a list of accepted words for all spell checking operations in
the repository.

#### In-line File

CSpell supports numerous methods to annotate your files to ignore words,
sections, etc.  This can be found in CSpell documentation.  Suggestion here is
to use a c-style comment at the top of the file to add words that should be
ignored just for this file.  Obviously this has the highest maintenance cost so
it should only be used for file unique words.

``` c
// spell-checker:ignore unenroll, word2, word3
```

or

```ini
# spell-checker:ignore unenroll, word2, word3
```

### Markdown linting

The linter uses the configuration defined in `.markdownlint.yaml` file found at
the root of the repository.

#### In-line Ignore

See options listed here
<https://github.com/DavidAnson/markdownlint#configuration> to ignore rules,
ignore lines, or ignore files.
