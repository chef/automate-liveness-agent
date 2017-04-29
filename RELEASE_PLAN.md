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
rake compile_recipe && kitchen test
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

Start the agent. Take note of the log messages about the ruby heap
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

* Set the version
* Tag it
* Make a [github release](https://github.com/chef/automate-liveness-agent/releases)
