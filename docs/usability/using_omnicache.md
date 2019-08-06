# Omnicache

Omnicache, the tool, is a command line tool that helps setup and update an Omnicache. 

An Omnicache is just a bare repo with lots of remotes fetched so that, if configured, Stuart tools will use it as a reference when updating or cloning a repo.
This saves a lot of network bandwidth, disk space, and time if you develop with many workspaces on a single PC and can also be used to speed up CI.  

## Creating your Omnicache

You can setup your Omnicache many ways.  You can add config entries from numerous files or thru command line.  Try `Omnicache -h` for help.  Here are the steps for a simple empty installation.  

1. Make sure you have installed edk2toolext using Pip
2. Open cmd prompt
3. Create one
   ``` cmd
   omnicache --init <path>
   ```
4. At the end of the creation it will suggest setting the __OMNICACHE_PATH__ environment variable.  For best results do this. 

## Adding Config Entries

Config entries can be added when first creating the cache as well as any time by using the tool.  
Config entries can be added 1-by-1 from the command line or thru a config file. 

### Example of adding config entry

``` cmd
omnicache -a tianocore_edk2 https://github.com/tianocore/edk2.git --init %OMNICACHE_PATH%
omnicache -a openssl https://github.com/openssl/openssl.git True --init %OMNICACHE_PATH%
```

### Example Config

Copy the below sample and save it as __abc.yml__

``` yml
remotes:
- name: openssl
  url: https://github.com/openssl/openssl.git
  tag: true
- name: tianocore_edk2
  url: https://github.com/tianocore/edk2.git
```

Then run omnicache command to add the new entries.

``` cmd
omnicache -c abc.yml --init %OMNICACHE_PATH%
```

## Keeping your Omnicache Current

The Omnicache doesn't have to always be current.  If it gets stale it will still help but there will be more "cache misses". Since the Omnicache is just a git repo it can easily be updated by running git commands and since it is a bare repo it is trouble free to update.  The Omicache tool attempts to make this even easier.

### Windows Scheduled Task

If you want to use a scheduled task here is one way to do it on Windows.

1. Set the __OMNICACHE_PATH__ environment variable to your path
2. Create an __omnicache_update.bat__ file in your omnicache directory that contains

  ``` bat
  omnicache --init --fetch %OMNICACHE_PATH%
  ```

3. Create a temporary XML file on your desktop with the contents below named __"O_U.xml"__

  ``` xml
  <?xml version="1.0" encoding="UTF-16"?>
  <Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
    <Triggers>
      <CalendarTrigger>
        <StartBoundary>2019-01-04T8:00:00</StartBoundary>
        <ExecutionTimeLimit>PT2H</ExecutionTimeLimit>
        <Enabled>true</Enabled>
        <ScheduleByDay>
          <DaysInterval>1</DaysInterval>
        </ScheduleByDay>
      </CalendarTrigger>
    </Triggers>
    <Settings>
      <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
      <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
      <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
      <AllowHardTerminate>true</AllowHardTerminate>
      <StartWhenAvailable>false</StartWhenAvailable>
      <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
      <IdleSettings>
        <StopOnIdleEnd>true</StopOnIdleEnd>
        <RestartOnIdle>false</RestartOnIdle>
      </IdleSettings>
      <AllowStartOnDemand>true</AllowStartOnDemand>
      <Enabled>true</Enabled>
      <Hidden>false</Hidden>
      <RunOnlyIfIdle>false</RunOnlyIfIdle>
      <DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>
      <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
      <WakeToRun>false</WakeToRun>
      <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
      <Priority>7</Priority>
    </Settings>
    <Actions Context="Author">
      <Exec>
        <Command>cmd.exe</Command>
        <Arguments>/c omnicache_update.bat</Arguments>
        <WorkingDirectory>%OMNICACHE_PATH%</WorkingDirectory>
      </Exec>
    </Actions>
  </Task>
  ```

4. Open Cmd prompt and use SCHTASKS to create a task.

  ``` cmd
  SCHTASKS /Create /XML "O_U.xml" /TN "Omnicache Updater"
  ```

## Using Omnicache for stuart_setup

Set the environment variable __OMNICACHE_PATH__ for automatic usage.
To provide a path manually:

```cmd
stuart_setup --omnicache <path>
stuart_ci_setup --omnicache <path>
```

## Using Omnicache for git clone

Current best practice is to setup a bashrc alias if using git for windows in gitbash.

``` bash
alias gcl='git clone --reference ${OMNICACHE_PATH}’  
```

Then every git clone you want to do you can call `gcl <url> <folder>` instead of `git clone <url> <folder>`

## Warnings

* Removing the omnicache from your PC can cause problems in your repos. Read up on --reference in git for methods to resolve this before deleting the omnicache.  

* Bug in `git submodule update --recursive --reference <path>` .  This doesn't work as git appends the recursive submodule path to the reference path.  Contacting git maintainers for clarity.  

* Tags:  tags are not namespaced by remote therefore conflicts could occur.  Suggestion is to not pull tags unless required.  Stack exchange has a few other ideas but nothing implemented yet.

* Older versions of the omnicache tool used `-u true` to update.  Newer versions just require `-u` or `--fetch`.  

* Since `-a` is a varable length argument list it is best to always add the `--init` parameter as the last parameter before the cache_dir positional argument.  This way python argparse knows positional args from the `-a` optional args.


----
## A second tutorial of Omnicache
----

## The Omnicache or how I learned to stop worrying and love the allrepo

## The Genesis

Many repos in the tree have common roots and share a very similar codebase. In order to speed up clone times for our CI builds as well as for personal use, we realized you can clone a repo using a reference repository.

```bash
git clone {{URL}} --reference ../some-directory
```

Another feature that came to light is that you can use git to create an omnirepostitory. You can have all the objects stored into one place and git will query this repo for any objects it wishes to fetch and if they aren't found, it will then request them from upstream.

We created some helper functions to wrap around this. It can be called by omnicache.

## Creating a new omnicache

```bash
omnicache --init ../omnicache
```

You can optionally use

```bash
omnicache --new ../omnicache
```

The difference between the two is that new will fail if something exists there, init does not.

## Feeding- I mean, Adding to the omnicache

```bash
omnicache -a <name> <url> <Sync tags optional default=False> ../omnicache
omnicache --add <name> <url> <Sync tags optional default=False> ../omnicache
```

  (Either of these will work)

## Updating the omnicache

Now that you're a proud owner of an omnicache, you need to take care to update it semi-regularly.

```bash
omnicache --update ../omnicache
omnicache -u ../omnicache
```

  (Either of these will work)

## Know what's in the cache

You can find out what is in your cache by listing it's contents.

```bash
omnicache --list ../omnicache
```

## Assimilation into the Omnicache

Sometimes you have a folder where all the repos are already cloned (either as submodules or separate folders). You can scan them all into the omnicache by using the scan feature.

```bash
omnicache --scan ../folder ../omnicache
```

This will add unique repos/submodules that it finds in the top level folders in ../folder. Unique is determined by URL.

## Fighting back against the Omnicache

If your omnicache has grown a touch too powerful, you can take control back in your life by removing items from the cache.

```bash
omnicache --remove {{name_of_repo}} ../omnicache
omnicache -r {{name_of_repo}} ../omnicache
```

## Using the Omnicache

Many of the tools are equipped to handle the omnicache and details on how to use them can be found in their respective documentations or help menus.
