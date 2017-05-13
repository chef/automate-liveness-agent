# RELEASE PLAN

## Acceptance Testing

#### Unit Tests

Run the unit tests against the compiled version of the agent:

```
TEST_BUILD_ARTIFACT=1 bundle exec rake
```

#### Kitchen Acceptance Tests

Run the full kitchen acceptance suite

```
rake compile_recipe
kitchen converge automate
kitchen test supported
```

#### Recipe and Init Script Testing

##### Recipe Multi-Run Test

Run this recipe at least 2x so we know it works continuously. This is tested
during the integration suite.

```
kitchen test PLATFORM -d never
kitchen login PLATFORM
sudo -i
INTERVAL=2 chef-client -z -c /tmp/kitchen/test-client.rb -j /tmp/kitchen/test-attrs.json
```

##### Init Script Acceptance Test

Test all the functions of the init script. Check the output of `ps` to
verify. These are all tested by the integration suite.

* start, when stopped, starts it
* start, when started, does not start another one
* stop, when started, stops it
* stop, when stopped, says service not running
* restart, when stopped, starts it
* restart, when running, stops the running one and starts a new one

##### Logging Test

Ensure the agent is correctly logging. The logfile should be owned by
the non-root user we create for the agent. This is tested by the integration
suite.

##### Chef Client Uninstall Detection

This only applies on UNIX-like systems.

Stop the agent and then start it with a more reasonable interval for
testing:

```
/etc/init.d/automate-liveness-agent stop
INTERVAL=1 /etc/init.d/automate-liveness-agent start
```

Uninstall the Chef Client package. System dependent, but `dpkg -P chef`
works on ubuntu.

Check the logs and confirm that the agent shut itself down:

```
tail /var/log/chef/automate-liveness-agent.log
```

#### Memory and Log Rotation Testing

Set the following environment variables:

```
INTERVAL=1
LOGGER_STRESS_MODE=1
```

`INTERVAL` controls the time that the agent waits between updates, in
seconds. `LOGGER_STRESS_MODE` sets the max file size for log files to
2k, so the log file will rotate more often.

The agent must have the following config enabled:

* `log_file` configured to log to a file (not `STDOUT`)
* `unprivileged_uid` and `unprivileged_gid` set to non-root values

Start the agent. The full command inside a kitchen VM is:

```
/etc/init.d/automate-liveness-agent stop
INTERVAL=1 LOGGER_STRESS_MODE=1 /etc/init.d/automate-liveness-agent start
```

Take note of the log messages about the ruby heap
stats; they look like this:

```
Total ruby objects: 23638; Free heap slots: 6274
```

Also note the process' RSS memory usage.

Run the agent until it has completed a full log rotation cycle. That is,
the initial log should be rotated to `logfile.0` and replaced with a new
file, and then rotated again so that the very first logfile is deleted.

Next get the ruby heap stats from the log. These should be identical to
the stats from when the agent first started.

Check the process' RSS. This may grow slightly as ruby's heap fragments
a bit, but definitely should not exceed 20MB.

## Ship It!

#### Tag It

We're using annotated tags in the `v0.1.0` format:

```
git tag -a v$VERSION
git push origin --tags
```

#### Build the Recipe

```
bundle exec rake compile_recipe
```

#### Github Release

Go to the [github releases](https://github.com/chef/automate-liveness-agent/releases)
page. Click the "Draft a New Release" button on the right.

Enter the name of the tag you just created and fill out the title and
description.

Upload the compiled recipe (from `build/automate-liveness-recipe.rb`) to
the release.

Click "Publish release"

#### Update the Version Number for Dev

Set the version in `lib/automate_liveness_agent/version.rb`

Commit and push the version number update.

#### Deploy the New Release to Chef Internal Infrastructure

TODO: describe this process:
* how to deploy it
* how to confirm it works
