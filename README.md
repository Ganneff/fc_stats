# fc_stats

A munin plugin to collect statistics from fibre channel host data once
every second.

## How
The plugin uses the /sys filesystem and reads statistic files from
there. Statistics are read once per second and written to cachefiles;
whenever munin asks for the data, the content of the cachefile is
send.

## Usage
Compile (or load a released binary, if one is there) and put the
binary somewhere. Then link it into the munin plugins dir.

When first called without arguments, fc_stats will spawn itself into
the background to gather data. This can also be triggered by calling
it with the `acquire` parameter.

## Local build
Use cargo build as usual. Note that the release build contains much
less logging code than the debug build, so if you want to find out,
why something does not work as planned, ensure to use a debug build
(`cargo build` instead of `cargo build --release`).
