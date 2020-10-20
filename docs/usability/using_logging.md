# edk2 logging

edk2_logging is a collection of utilities to manage logging.

There are four different ways to create handlers.

 1. setup_txt_logger - a handler that outputs a txt file
 2. setup_markdown_logger - a handler that outputs a markdown file with an output file
 3. setup_console_logging - a handler that logs to the console with optional colors
 4. create_output_stream - a handler that has an in-memory stream that you can later read from

setup_logging is a helper function that creates 1-3 of the handlers. The output_stream is used for plugins in mu_build
so they can keep track of compiler output

## General Practice

+ All modules that are not PlatformBuilder or stuart_ci_build should request a named logger like this:

 ```python
  logging.getLogger("Git")
 ```

+ Modules that are not the root module get downgraded a level (ie. critical -> warning)
