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
    io::{self, Write},
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tempfile::NamedTempFile;

/// Return list of fibrechannel hosts or error out
fn get_hosts() -> Result<Vec<String>, Box<dyn Error>> {
    Ok(read_dir("/sys/class/fc_host/")?
        .into_iter()
        .map(|name| {
            name.map(|entry| entry.file_name().to_str().unwrap().to_string())
                .unwrap()
        })
        .collect::<Vec<String>>())
}

/// Print out munin config data
fn config() -> Result<(), Box<dyn Error>> {
    for hname in get_hosts()? {
        println!("multigraph san_{0}", hname);
        println!("graph_title SAN port status {0}", hname);
        println!("graph_category disk");
        println!("graph_vlabel SAN port status {0}", hname);
        println!("graph_scale no",);
        println!("update_rate 1",);
        println!(
            "graph_data_size custom 1d, 1s for 1d, 5s for 2d, 10s for 7d, 1m for 1t, 5m for 1y",
        );
        println!("{0}_fcp_input_megabytes.label {0} Mb/s", hname);
        println!("{0}_fcp_input_megabytes.draw LINE", hname);
        println!("{0}_fcp_input_megabytes.type COUNTER", hname);
        println!("{0}_fcp_input_megabytes.min 0", hname);
        println!("{0}_fcp_input_megabytes.graph no", hname);
        println!(
            "{0}_fcp_input_megabytes.cdef {0}_fcp_input_megabytes,1,*",
            hname
        );
        println!("{0}_fcp_output_megabytes.label {0} Mb/s", hname);
        println!("{0}_fcp_output_megabytes.draw LINE", hname);
        println!("{0}_fcp_output_megabytes.type COUNTER", hname);
        println!("{0}_fcp_output_megabytes.min 0", hname);
        println!(
            "{0}_fcp_output_megabytes.negative {0}_fcp_input_megabytes",
            hname
        );
        println!(
            "{0}_fcp_output_megabytes.cdef {0}_fcp_output_megabytes,1,*",
            hname
        );
        println!("{0}_fcp_input_requests.label {0} requests", hname);
        println!("{0}_fcp_input_requests.draw LINE", hname);
        println!("{0}_fcp_input_requests.type COUNTER", hname);
        println!("{0}_fcp_input_requests.min 0", hname);
        println!("{0}_fcp_input_requests.graph no", hname);
        println!(
            "{0}_fcp_input_requests.cdef {0}_fcp_input_requests,1,*",
            hname
        );
        println!("{0}_fcp_output_requests.label {0} requests", hname);
        println!("{0}_fcp_output_requests.draw LINE", hname);
        println!("{0}_fcp_output_requests.type COUNTER", hname);
        println!("{0}_fcp_output_requests.min 0", hname);
        println!(
            "{0}_fcp_output_requests.negative {0}_fcp_input_requests",
            hname
        );
        println!(
            "{0}_fcp_output_requests.cdef {0}_fcp_output_requests,1,*",
            hname
        );
        println!("{0}_fcp_packet_aborts.label {0} FCP Packet Aborts", hname);
        println!("{0}_fcp_packet_aborts.draw LINE", hname);
        println!("{0}_fcp_packet_aborts.type COUNTER", hname);
        println!("{0}_fcp_packet_aborts.min 0", hname);
        println!("{0}_invalid_crc_count.label {0} Invalid CRC Count", hname);
        println!("{0}_invalid_crc_count.draw LINE", hname);
        println!("{0}_invalid_crc_count.type COUNTER", hname);
        println!("{0}_invalid_crc_count.min 0", hname);
        println!(
            "{0}_invalid_tx_word_count.label {0} Invalid TX Word Count",
            hname
        );
        println!("{0}_invalid_tx_word_count.draw LINE", hname);
        println!("{0}_invalid_tx_word_count.type COUNTER", hname);
        println!("{0}_invalid_tx_word_count.min 0", hname);
        println!("{0}_link_failure_count.label {0} Link Failure Count", hname);
        println!("{0}_link_failure_count.draw LINE", hname);
        println!("{0}_link_failure_count.type COUNTER", hname);
        println!("{0}_link_failure_count.min 0", hname);

        println!("multigraph san_{0}.san_{0}_mega", hname);
        println!("graph_title SAN port transfer {0}", hname);
        println!("graph_category disk",);
        println!("graph_vlabel SAN port status {0}", hname);
        println!("graph_scale no",);
        println!("update_rate 1",);
        println!(
            "graph_data_size custom 1d, 1s for 1d, 5s for 2d, 10s for 7d, 1m for 1t, 5m for 1y",
        );
        println!("san_{0}_fcp_input_megabytes.label {0} Mb/s", hname);
        println!("san_{0}_fcp_input_megabytes.draw LINE", hname);
        println!("san_{0}_fcp_input_megabytes.type COUNTER", hname);
        println!("san_{0}_fcp_input_megabytes.min 0", hname);
        println!("san_{0}_fcp_input_megabytes.graph no", hname);
        println!(
            "san_{0}_fcp_input_megabytes.cdef san_{0}_fcp_input_megabytes,1,*",
            hname
        );
        println!("san_{0}_fcp_output_megabytes.label {0} Mb/s", hname);
        println!("san_{0}_fcp_output_megabytes.draw LINE", hname);
        println!("san_{0}_fcp_output_megabytes.type COUNTER", hname);
        println!("san_{0}_fcp_output_megabytes.min 0", hname);
        println!(
            "san_{0}_fcp_output_megabytes.negative san_{0}_fcp_input_megabytes",
            hname
        );
        println!(
            "san_{0}_fcp_output_megabytes.cdef san_{0}_fcp_output_megabytes,1,*",
            hname
        );

        println!("multigraph san_{0}.san_{0}_requests", hname);
        println!("graph_title SAN port requests {0}", hname);
        println!("graph_category disk",);
        println!("graph_vlabel SAN port requests {0}", hname);
        println!("graph_scale no",);
        println!("update_rate 1",);
        println!(
            "graph_data_size custom 1d, 1s for 1d, 5s for 2d, 10s for 7d, 1m for 1t, 5m for 1y",
        );
        println!("san_{0}_fcp_input_requests.label {0} requests", hname);
        println!("san_{0}_fcp_input_requests.draw LINE", hname);
        println!("san_{0}_fcp_input_requests.type COUNTER", hname);
        println!("san_{0}_fcp_input_requests.min 0", hname);
        println!("san_{0}_fcp_input_requests.graph no", hname);
        println!(
            "san_{0}_fcp_input_requests.cdef san_{0}_fcp_input_requests,1,*",
            hname
        );
        println!("san_{0}_fcp_output_requests.label {0} requests", hname);
        println!("san_{0}_fcp_output_requests.draw LINE", hname);
        println!("san_{0}_fcp_output_requests.type COUNTER", hname);
        println!("san_{0}_fcp_output_requests.min 0", hname);
        println!(
            "san_{0}_fcp_output_requests.negative san_{0}_fcp_input_requests",
            hname
        );
        println!(
            "san_{0}_fcp_output_requests.cdef san_{0}_fcp_output_requests,1,*",
            hname
        );

        println!("multigraph san_{0}.san_{0}_other", hname);
        println!("graph_title SAN port stats {0}", hname);
        println!("graph_category disk",);
        println!("graph_vlabel SAN port stats {0}", hname);
        println!("graph_scale no",);
        println!("update_rate 1",);
        println!(
            "graph_data_size custom 1d, 1s for 1d, 5s for 2d, 10s for 7d, 1m for 1t, 5m for 1y",
        );
        println!(
            "san_{0}_fcp_packet_aborts.label {0} FCP Packet Aborts",
            hname
        );
        println!("san_{0}_fcp_packet_aborts.draw LINE", hname);
        println!("san_{0}_fcp_packet_aborts.type COUNTER", hname);
        println!("san_{0}_fcp_packet_aborts.min 0", hname);
        println!(
            "san_{0}_invalid_crc_count.label {0} Invalid CRC Count",
            hname
        );
        println!("san_{0}_invalid_crc_count.draw LINE", hname);
        println!("san_{0}_invalid_crc_count.type COUNTER", hname);
        println!("san_{0}_invalid_crc_count.min 0", hname);
        println!(
            "san_{0}_invalid_tx_word_count.label {0} Invalid TX Word Count",
            hname
        );
        println!("san_{0}_invalid_tx_word_count.draw LINE", hname);
        println!("san_{0}_invalid_tx_word_count.type COUNTER", hname);
        println!("san_{0}_invalid_tx_word_count.min 0", hname);
        println!(
            "san_{0}_link_failure_count.label {0} Link Failure Count",
            hname
        );
        println!("san_{0}_link_failure_count.draw LINE", hname);
        println!("san_{0}_link_failure_count.type COUNTER", hname);
        println!("san_{0}_link_failure_count.min 0", hname);
    }

    Ok(())
}

/// Parse a sysfs value from fc_host from hex to <<u128>>
macro_rules! parsedp {
    ($host:expr, $dp:expr) => {
        parse::<u128>(
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
    ($file:expr) => {
        OpenOptions::new()
            .create(true) // If not there, create
            .write(true) // We want to write
            .append(true) // We want to append
            .open($file)
            .expect("Couldn't open cachefile")
    };
}

/// Write out 2 lines, one to each given (already open!) file
macro_rules! wout {
    ($cfd:expr, $sfd:expr, $host:expr, $dp:expr, $epoch:expr, $data:expr) => {
        writeln!($cfd, "san_{0}_{1}.value {2}:{3}", $host, $dp, $epoch, $data)?;
        writeln!($sfd, "san_{0}_{1}.value {2}:{3}", $host, $dp, $epoch, $data)?;
    };
}

/// Gather data from sysfs
macro_rules! gather_data {
    ($dp:expr, $cachepath:expr, $host:expr, $epoch:expr) => {
        let cachefile = Path::join($cachepath, format!("munin.fc_stats.value.{}", $host));
        let mut cachefd = openfd!(cachefile);

        match $dp {
            "fcp_input_megabytes" | "fcp_output_megabytes" => {
                let mbcachefile =
                    Path::join($cachepath, format!("munin.fc_stats.value.{}.mega", $host));
                let mut mbcachefd = openfd!(mbcachefile);
                let data: u128 = parsedp!($host, $dp);
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
/// u128, that ought to be big enough to not overflow.
fn acquire(cachepath: &Path, pidfile: &Path) -> Result<(), Box<dyn Error>> {
    trace!("Going to daemonize");

    let daemonize = Daemonize::new()
        .pid_file(pidfile)
        .chown_pid_file(true)
        .working_directory("/tmp");

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
    match daemonize.start() {
        Ok(_) => {
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
                let epoch = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Time gone broken, what?")
                    .as_secs(); // without the nanosecond part

                for host in &hosts {
                    for dp in DATA {
                        gather_data!(dp, cachepath, host, epoch);
                    }
                }

                // Sleep for the rest of the second
                loop_helper.loop_sleep();
            }
        }
        Err(e) => {
            error!("Something gone wrong: {}", e);
            Err(Box::new(e))
        }
    }
}

/// Hand out the collected interface data
///
/// Basically a "mv file tmpfile && cat tmpfile && rm tmpfile",
/// as the file is already in proper format
fn fetch(cache: &Path) -> Result<(), Box<dyn Error>> {
    #[allow(clippy::redundant_static_lifetimes)]
    const NAMES: [&'static str; 4] = ["", ".mega", ".requests", ".other"];

    // We want to write possibly large amount to stdout, take and lock it
    let stdout = io::stdout();
    let mut handle = stdout.lock();

    for host in get_hosts()? {
        for fname in NAMES {
            let cf = Path::join(cache, format!("munin.fc_stats.value.{}{}", host, fname));
            trace!("CF: {:?}", cf);
            let fp = NamedTempFile::new_in(cache)?;
            trace!("FP Temp: {:?}", fp);
            // Rename the cache file, to ensure that acquire doesn't add data
            // between us outputting data and deleting the file
            rename(&cf, &fp)?;
            // Want to read the tempfile now
            let mut fetchfile = std::fs::File::open(&fp)?;
            // And ask io::copy to just take it all and show it into stdout
            io::copy(&mut fetchfile, &mut handle)?;
        }
    }
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
