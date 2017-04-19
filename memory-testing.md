# Memory Testing

Automate liveness agent is intended to be a long-lived service, so it
needs to consume a (preferably low) stable amount of memory over time.

Each cycle, the agent logs its total ruby objects and free heap slots,
as provided by `ObjectSpace.count_objects`. After one or two cycles,
these numbers should remain stable.

For definitions of what the object counts provided by `ObjectSpace`
represent, see the code comment: https://github.com/ruby/ruby/blob/edd063ab1a08eb362179837418e20f50bb837d95/gc.c#L3266-L3296
and tests: https://github.com/ruby/ruby/blob/edd063ab1a08eb362179837418e20f50bb837d95/test/ruby/test_gc.rb#L92-L94

Since the agent just sleeps between sending updates, it's useful for
memory testing to reduce the amount of sleep time. This can be achieved
by setting the `INTERVAL` environment variable.

