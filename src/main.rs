//! fc_stats - Collect SAN port data for munin every second
//!
// SPDX-License-Identifier:  GPL-3.0-only

#![warn(missing_docs)]

use daemonize::Daemonize;
use fs2::FileExt;
use log::{debug, error, info, trace, warn};
use parse_int::parse;
use simple_logger::SimpleLogger;
use spin_sleep::LoopHelper;
use std::{
    env,
    error::Error,
    fs::{read_dir, rename, File, OpenOptions},
    io::{self, BufWriter, Write},
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tempfile::NamedTempFile;

/// Return list of fibrechannel hosts or error out
///
/// Simply a list of entries in the sysfs tree. Entries there usually
/// named host? with ? == one digit, though I have not seen a
/// particular scheme of when its 0, 1, 2 or 3.
fn get_hosts() -> Result<Vec<String>, Box<dyn Error>> {
    // A list of "hosts" AKA entries in the sysfs tree
    Ok(read_dir("/sys/class/fc_host/")?
        .into_iter()
        .map(|name| {
            name.map(|entry| entry.file_name().to_str().unwrap().to_string())
                .unwrap()
        })
        .collect::<Vec<String>>())
}

/// Print out munin config data
///
/// Will print out config data per host as listed from [get_hosts],
/// preparing for multiple graphs, one summary and 3 detail ones.
fn config() -> Result<(), Box<dyn Error>> {
    // We want to write a large amount to stdout, take and lock it
    let stdout = io::stdout();
    let mut handle = BufWriter::with_capacity(16384, stdout.lock());

    for hname in get_hosts()? {
        writeln!(handle, "multigraph san_{0}", hname)?;
        writeln!(handle, "graph_title SAN port status {0}", hname)?;
        writeln!(handle, "graph_category disk")?;
        writeln!(handle, "graph_vlabel SAN port status {0}", hname)?;
        writeln!(handle, "graph_scale no",)?;
        writeln!(handle, "update_rate 1",)?;
        writeln!(
            handle,
            "graph_data_size custom 1d, 1s for 1d, 5s for 2d, 10s for 7d, 1m for 1t, 5m for 1y",
        )?;
        writeln!(handle, "{0}_fcp_input_megabytes.label {0} Mb/s", hname)?;
        writeln!(handle, "{0}_fcp_input_megabytes.draw LINE", hname)?;
        writeln!(handle, "{0}_fcp_input_megabytes.type COUNTER", hname)?;
        writeln!(handle, "{0}_fcp_input_megabytes.min 0", hname)?;
        writeln!(handle, "{0}_fcp_input_megabytes.graph no", hname)?;
        writeln!(
            handle,
            "{0}_fcp_input_megabytes.cdef {0}_fcp_input_megabytes,1,*",
            hname
        )?;
        writeln!(handle, "{0}_fcp_output_megabytes.label {0} Mb/s", hname)?;
        writeln!(handle, "{0}_fcp_output_megabytes.draw LINE", hname)?;
        writeln!(handle, "{0}_fcp_output_megabytes.type COUNTER", hname)?;
        writeln!(handle, "{0}_fcp_output_megabytes.min 0", hname)?;
        writeln!(
            handle,
            "{0}_fcp_output_megabytes.negative {0}_fcp_input_megabytes",
            hname
        )?;
        writeln!(
            handle,
            "{0}_fcp_output_megabytes.cdef {0}_fcp_output_megabytes,1,*",
            hname
        )?;
        writeln!(handle, "{0}_fcp_input_requests.label {0} requests", hname)?;
        writeln!(handle, "{0}_fcp_input_requests.draw LINE", hname)?;
        writeln!(handle, "{0}_fcp_input_requests.type COUNTER", hname)?;
        writeln!(handle, "{0}_fcp_input_requests.min 0", hname)?;
        writeln!(handle, "{0}_fcp_input_requests.graph no", hname)?;
        writeln!(
            handle,
            "{0}_fcp_input_requests.cdef {0}_fcp_input_requests,1,*",
            hname
        )?;
        writeln!(handle, "{0}_fcp_output_requests.label {0} requests", hname)?;
        writeln!(handle, "{0}_fcp_output_requests.draw LINE", hname)?;
        writeln!(handle, "{0}_fcp_output_requests.type COUNTER", hname)?;
        writeln!(handle, "{0}_fcp_output_requests.min 0", hname)?;
        writeln!(
            handle,
            "{0}_fcp_output_requests.negative {0}_fcp_input_requests",
            hname
        )?;
        writeln!(
            handle,
            "{0}_fcp_output_requests.cdef {0}_fcp_output_requests,1,*",
            hname
        )?;
        writeln!(
            handle,
            "{0}_fcp_packet_aborts.label {0} FCP Packet Aborts",
            hname
        )?;
        writeln!(handle, "{0}_fcp_packet_aborts.draw LINE", hname)?;
        writeln!(handle, "{0}_fcp_packet_aborts.type COUNTER", hname)?;
        writeln!(handle, "{0}_fcp_packet_aborts.min 0", hname)?;
        writeln!(
            handle,
            "{0}_invalid_crc_count.label {0} Invalid CRC Count",
            hname
        )?;
        writeln!(handle, "{0}_invalid_crc_count.draw LINE", hname)?;
        writeln!(handle, "{0}_invalid_crc_count.type COUNTER", hname)?;
        writeln!(handle, "{0}_invalid_crc_count.min 0", hname)?;
        writeln!(
            handle,
            "{0}_invalid_tx_word_count.label {0} Invalid TX Word Count",
            hname
        )?;
        writeln!(handle, "{0}_invalid_tx_word_count.draw LINE", hname)?;
        writeln!(handle, "{0}_invalid_tx_word_count.type COUNTER", hname)?;
        writeln!(handle, "{0}_invalid_tx_word_count.min 0", hname)?;
        writeln!(
            handle,
            "{0}_link_failure_count.label {0} Link Failure Count",
            hname
        )?;
        writeln!(handle, "{0}_link_failure_count.draw LINE", hname)?;
        writeln!(handle, "{0}_link_failure_count.type COUNTER", hname)?;
        writeln!(handle, "{0}_link_failure_count.min 0", hname)?;

        writeln!(handle, "multigraph san_{0}.san_{0}_mega", hname)?;
        writeln!(handle, "graph_title SAN port transfer {0}", hname)?;
        writeln!(handle, "graph_category disk",)?;
        writeln!(handle, "graph_vlabel SAN port status {0}", hname)?;
        writeln!(handle, "graph_scale no",)?;
        writeln!(handle, "update_rate 1",)?;
        writeln!(
            handle,
            "graph_data_size custom 1d, 1s for 1d, 5s for 2d, 10s for 7d, 1m for 1t, 5m for 1y",
        )?;
        writeln!(handle, "san_{0}_fcp_input_megabytes.label {0} Mb/s", hname)?;
        writeln!(handle, "san_{0}_fcp_input_megabytes.draw LINE", hname)?;
        writeln!(handle, "san_{0}_fcp_input_megabytes.type COUNTER", hname)?;
        writeln!(handle, "san_{0}_fcp_input_megabytes.min 0", hname)?;
        writeln!(handle, "san_{0}_fcp_input_megabytes.graph no", hname)?;
        writeln!(
            handle,
            "san_{0}_fcp_input_megabytes.cdef san_{0}_fcp_input_megabytes,1,*",
            hname
        )?;
        writeln!(handle, "san_{0}_fcp_output_megabytes.label {0} Mb/s", hname)?;
        writeln!(handle, "san_{0}_fcp_output_megabytes.draw LINE", hname)?;
        writeln!(handle, "san_{0}_fcp_output_megabytes.type COUNTER", hname)?;
        writeln!(handle, "san_{0}_fcp_output_megabytes.min 0", hname)?;
        writeln!(
            handle,
            "san_{0}_fcp_output_megabytes.negative san_{0}_fcp_input_megabytes",
            hname
        )?;
        writeln!(
            handle,
            "san_{0}_fcp_output_megabytes.cdef san_{0}_fcp_output_megabytes,1,*",
            hname
        )?;

        writeln!(handle, "multigraph san_{0}.san_{0}_requests", hname)?;
        writeln!(handle, "graph_title SAN port requests {0}", hname)?;
        writeln!(handle, "graph_category disk",)?;
        writeln!(handle, "graph_vlabel SAN port requests {0}", hname)?;
        writeln!(handle, "graph_scale no",)?;
        writeln!(handle, "update_rate 1",)?;
        writeln!(
            handle,
            "graph_data_size custom 1d, 1s for 1d, 5s for 2d, 10s for 7d, 1m for 1t, 5m for 1y",
        )?;
        writeln!(
            handle,
            "san_{0}_fcp_input_requests.label {0} requests",
            hname
        )?;
        writeln!(handle, "san_{0}_fcp_input_requests.draw LINE", hname)?;
        writeln!(handle, "san_{0}_fcp_input_requests.type COUNTER", hname)?;
        writeln!(handle, "san_{0}_fcp_input_requests.min 0", hname)?;
        writeln!(handle, "san_{0}_fcp_input_requests.graph no", hname)?;
        writeln!(
            handle,
            "san_{0}_fcp_input_requests.cdef san_{0}_fcp_input_requests,1,*",
            hname
        )?;
        writeln!(
            handle,
            "san_{0}_fcp_output_requests.label {0} requests",
            hname
        )?;
        writeln!(handle, "san_{0}_fcp_output_requests.draw LINE", hname)?;
        writeln!(handle, "san_{0}_fcp_output_requests.type COUNTER", hname)?;
        writeln!(handle, "san_{0}_fcp_output_requests.min 0", hname)?;
        writeln!(
            handle,
            "san_{0}_fcp_output_requests.negative san_{0}_fcp_input_requests",
            hname
        )?;
        writeln!(
            handle,
            "san_{0}_fcp_output_requests.cdef san_{0}_fcp_output_requests,1,*",
            hname
        )?;

        writeln!(handle, "multigraph san_{0}.san_{0}_other", hname)?;
        writeln!(handle, "graph_title SAN port stats {0}", hname)?;
        writeln!(handle, "graph_category disk",)?;
        writeln!(handle, "graph_vlabel SAN port stats {0}", hname)?;
        writeln!(handle, "graph_scale no",)?;
        writeln!(handle, "update_rate 1",)?;
        writeln!(
            handle,
            "graph_data_size custom 1d, 1s for 1d, 5s for 2d, 10s for 7d, 1m for 1t, 5m for 1y",
        )?;
        writeln!(
            handle,
            "san_{0}_fcp_packet_aborts.label {0} FCP Packet Aborts",
            hname
        )?;
        writeln!(handle, "san_{0}_fcp_packet_aborts.draw LINE", hname)?;
        writeln!(handle, "san_{0}_fcp_packet_aborts.type COUNTER", hname)?;
        writeln!(handle, "san_{0}_fcp_packet_aborts.min 0", hname)?;
        writeln!(
            handle,
            "san_{0}_invalid_crc_count.label {0} Invalid CRC Count",
            hname
        )?;
        writeln!(handle, "san_{0}_invalid_crc_count.draw LINE", hname)?;
        writeln!(handle, "san_{0}_invalid_crc_count.type COUNTER", hname)?;
        writeln!(handle, "san_{0}_invalid_crc_count.min 0", hname)?;
        writeln!(
            handle,
            "san_{0}_invalid_tx_word_count.label {0} Invalid TX Word Count",
            hname
        )?;
        writeln!(handle, "san_{0}_invalid_tx_word_count.draw LINE", hname)?;
        writeln!(handle, "san_{0}_invalid_tx_word_count.type COUNTER", hname)?;
        writeln!(handle, "san_{0}_invalid_tx_word_count.min 0", hname)?;
        writeln!(
            handle,
            "san_{0}_link_failure_count.label {0} Link Failure Count",
            hname
        )?;
        writeln!(handle, "san_{0}_link_failure_count.draw LINE", hname)?;
        writeln!(handle, "san_{0}_link_failure_count.type COUNTER", hname)?;
        writeln!(handle, "san_{0}_link_failure_count.min 0", hname)?;
    }
    // And flush it, so it can also deal with possible errors
    handle.flush()?;

    Ok(())
}

/// Parse a sysfs value from fc_host from hex to <<u128>>
macro_rules! parsedp {
    ($host:ident, $dp:ident) => {
        parse::<u64>(
            std::fs::read_to_string(
                Path::new("/sys/class/fc_host")
                    .join($host)
                    .join("statistics")
                    .join($dp),
            )?
            .trim(),
        )?
    };
}

/// Open a file for appending
macro_rules! openfd {
    ($file:ident) => {
        BufWriter::new(
            OpenOptions::new()
                .create(true) // If not there, create
                .write(true) // We want to write
                .append(true) // We want to append
                .open($file)?,
        )
    };
}

/// Write out 2 lines, one to each given (already open!) file
macro_rules! wout {
    ($cfd:ident, $sfd:ident, $host:ident, $dp:ident, $epoch:ident, $data:ident) => {
        writeln!($cfd, "{0}_{1}.value {2}:{3}", $host, $dp, $epoch, $data)?;
        writeln!($sfd, "san_{0}_{1}.value {2}:{3}", $host, $dp, $epoch, $data)?;
    };
}

/// Gather data from sysfs and store into cachefile
macro_rules! gather_data {
    ($dp:ident, $cachepath:ident, $host:ident, $epoch:ident) => {
        let cachefile = Path::join($cachepath, format!("munin.fc_stats.value.{}", $host));
        let mut cachefd = openfd!(cachefile);

        match $dp {
            "fcp_input_megabytes" | "fcp_output_megabytes" => {
                let mbcachefile =
                    Path::join($cachepath, format!("munin.fc_stats.value.{}.mega", $host));
                let mut mbcachefd = openfd!(mbcachefile);
                let data: u64 = parsedp!($host, $dp);
                wout!(cachefd, mbcachefd, $host, $dp, $epoch, data);
            }
            "fcp_input_requests" | "fcp_output_requests" => {
                let rqcachefile = Path::join(
                    $cachepath,
                    format!("munin.fc_stats.value.{}.requests", $host),
                );
                let mut rqcachefd = openfd!(rqcachefile);
                let data: u128 = parsedp!($host, $dp);
                wout!(cachefd, rqcachefd, $host, $dp, $epoch, data);
            }
            &_ => {
                let ocachefile =
                    Path::join($cachepath, format!("munin.fc_stats.value.{}.other", $host));
                let mut ocachefd = openfd!(ocachefile);
                let data: u128 = parsedp!($host, $dp);
                wout!(cachefd, ocachefd, $host, $dp, $epoch, data);
            }
        }
    };
}

/// Gather the data from the system.
///
/// Daemonize into background and then run a loop forever, that
/// fetches data once a second and appends it to the given cachefile.
///
/// We read the values from the statistic files and parse them to a
/// [u64], that ought to be big enough to not overflow.
fn acquire(cachepath: &Path, pidfile: &Path) -> Result<(), Box<dyn Error>> {
    trace!("Going to daemonize");

    // Those are never (outside recompile) going to change, so make it
    // a const. We are intereted in those datapoints for the fc_stats.
    // Entries here are filenames in
    // /sys/class/fc_host/HOST/statistics and are expected to show hex
    // numbers.
    #[allow(clippy::redundant_static_lifetimes)]
    const DATA: [&'static str; 8] = [
        "fcp_input_megabytes",
        "fcp_input_requests",
        "fcp_output_megabytes",
        "fcp_output_requests",
        "fcp_packet_aborts",
        "invalid_crc_count",
        "invalid_tx_word_count",
        "link_failure_count",
    ];

    // We want to run as daemon, so prepare
    let daemonize = Daemonize::new()
        .pid_file(pidfile)
        .chown_pid_file(true)
        .working_directory("/tmp");

    // And off into the background we go
    daemonize.start()?;

    // The loop helper makes it easy to repeat a loop once a second
    let mut loop_helper = LoopHelper::builder().build_with_target_rate(1); // Only once a second

    // If we put this into the loop, we would be reacting to a
    // changed host situation, like when someone is doing a
    // manual forced reset of them. OTOH that would mean
    // recalculating this once a second, and that is really
    // not worth it, as such a manual reset happens something
    // like once a year only. We require a restart then.
    let hosts = get_hosts()?;

    // We run forever
    loop {
        // Let loop helper prepare
        loop_helper.loop_start();

        // We need the current epoch
        let epoch = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(); // without the nanosecond part

        // Look at each detected fc host
        for host in &hosts {
            // And gather the data we are interested in
            for dp in DATA {
                gather_data!(dp, cachepath, host, epoch);
            }
        }

        // Sleep for the rest of the second
        loop_helper.loop_sleep();
    }
}

/// Hand out the collected interface data
///
/// Basically a "mv file tmpfile && cat tmpfile && rm tmpfile", as the
/// file is already in proper format. Adds a "header" per file needed
/// for the multigraph setup.
fn fetch(cache: &Path) -> Result<(), Box<dyn Error>> {
    // Hardcoded list of names
    #[allow(clippy::redundant_static_lifetimes)]
    const NAMES: [&'static str; 4] = ["", ".mega", ".requests", ".other"];

    // We want to write possibly large amount to stdout, take and lock it
    let stdout = io::stdout();
    // And if we put a bufwriter in between, things use way less syscalls, as otherwise
    // writeln is triggering it every few bytes
    let mut handle = BufWriter::with_capacity(32768, stdout.lock());
    for host in get_hosts()? {
        for fname in NAMES {
            // Construct the filename
            let valfile = Path::join(cache, format!("munin.fc_stats.value.{}{}", host, fname));
            trace!("Value file: {:?}", valfile);
            // And we need a tempfile, so we can mv the actual file over
            let tempfile = NamedTempFile::new_in(cache)?;
            trace!("Temp file: {:?}", tempfile);
            // Rename the cache file, to ensure that acquire doesn't add data
            // between us outputting data and deleting the file
            rename(&valfile, &tempfile)?;
            // Want to read the tempfile now
            let mut fetchfile = std::fs::File::open(&tempfile)?;

            // Write header depending on the filename, to match what
            // config() has given munin
            match fname {
                ".mega" | ".requests" | ".other" => {
                    writeln!(
                        handle,
                        "multigraph san_{0}.san_{0}_{1}",
                        host,
                        fname.replace(".", "")
                    )?;
                }
                &_ => {
                    writeln!(handle, "multigraph san_{0}", host)?;
                }
            }
            // And ask io::copy to just take it all and shove it into stdout
            io::copy(&mut fetchfile, &mut handle)?;
        }
    }
    // Ensure the bufWriter is flushed, allows it to deal with possiblke errors.
    handle.flush()?;
    Ok(())
}

/// Manage it all.
///
/// Note that, while we do have extensive logging statements all over
/// the code, we use the crates feature to **not** compile in levels
/// we do not want. So in devel/debug builds, we have all levels
/// including trace! available, release build will only show warn! and
/// error! logs (tiny amount).
fn main() {
    SimpleLogger::new().init().unwrap();
    info!("fc_stats started");

    // Store arguments for later use
    let args: Vec<String> = env::args().collect();

    // Where is our plugin state directory?
    let plugstate = env::var("MUNIN_PLUGSTATE").unwrap_or_else(|_| "/tmp".to_owned());
    debug!("Plugin State: {:#?}", plugstate);
    // Put our cache file there
    let cache = Path::new(&plugstate);
    debug!("Cache: {:?}", cache);
    // Our pid is stored here - we also use it to detect if the daemon
    // part is running, and if not, to start it when called to fetch
    // data.
    let pidfile = Path::new(&plugstate).join("munin.fc_stats.pid");
    debug!("PIDfile: {:?}", pidfile);

    // Does the master support dirtyconfig?
    let dirtyconfig = match env::var("MUNIN_CAP_DIRTYCONFIG") {
        Ok(val) => val.eq(&"1"),
        Err(_) => false,
    };
    debug!("Dirtyconfig is: {:?}", dirtyconfig);

    // Now go over our other args and see what we are supposed to do
    match args.len() {
        // no arguments passed, print data
        1 => {
            trace!("No argument, assuming fetch");
            // Before we fetch we should ensure that we have a data
            // gatherer running. It locks the pidfile, so lets see if
            // it's locked or we can have it.
            let lockfile = !Path::exists(&pidfile) || {
                let lockedfile = File::open(&pidfile).expect("Could not open pidfile");
                lockedfile.try_lock_exclusive().is_ok()
            };

            // If we could lock, it appears that acquire isn't running. Start it.
            if lockfile {
                debug!("Could lock the pidfile, will spawn acquire now");
                Command::new(&args[0])
                    .arg("acquire".to_owned())
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("failed to execute acquire");
                debug!("Spawned, sleep for 1s, then continue");
                // Now we wait one second before going on, so the
                // newly spawned process had a chance to generate us
                // some data
                thread::sleep(Duration::from_secs(1));
                // }
            }
            // And now we can hand out the cached data
            if let Err(e) = fetch(cache) {
                error!("Could not fetch data: {}", e);
                std::process::exit(6);
            }
        }

        // one argument passed, check it and do something
        2 => match args[1].as_str() {
            "config" => {
                trace!("Called to hand out config");
                config().expect("Could not write out config");
                // If munin supports the dirtyconfig feature, we can hand out the data
                if dirtyconfig {
                    if let Err(e) = fetch(cache) {
                        error!("Could not fetch data: {}", e);
                        std::process::exit(6);
                    }
                };
            }
            "acquire" => {
                trace!("Called to gather data");
                // Only will ever process anything after this line, if
                // one process has our pidfile already locked, ie. if
                // another acquire is running. (Or if we can not
                // daemonize for another reason).
                if let Err(e) = acquire(cache, &pidfile) {
                    error!("Error: {}", e);
                    std::process::exit(5);
                };
            }
            _ => {
                error!("Unknown command {}", args[1]);
                std::process::exit(3);
            }
        },
        // all the other cases
        _ => {
            error!("Unknown number of arguments");
            std::process::exit(4);
        }
    }
    info!("All done");
}
