//! fc_stats - Collect SAN port data for munin every second
//!
// SPDX-License-Identifier:  GPL-3.0-only

#![warn(missing_docs)]

use anyhow::Result;
use log::{info, trace, warn};
use munin_plugin::{Config, MuninPlugin};
use parse_int::parse;
use simple_logger::SimpleLogger;
use std::{
    fs::{read_dir, rename, OpenOptions},
    io::{self, BufWriter, Write},
    path::Path,
};
use tempfile::NamedTempFile;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct FcPlugin {
    /// Data points from SAN we want to see (entries in
    /// `/sys/class/fc_host/HOST/statistics`.
    fc_data_points: [&'static str; 8],

    /// Store filename endings we deal with
    endings: [&'static str; 4],

    /// FC "hosts" on the system
    /// Stored here, so we only need to read them once at startup time.
    hosts: Vec<String>,
}

impl FcPlugin {
    /// Return list of fibrechannel hosts or error out
    ///
    /// Simply a list of entries in the sysfs tree. Entries there usually
    /// named host? with ? == one digit, though I have not seen a
    /// particular scheme of when its 0, 1, 2 or 3.
    fn get_hosts() -> Result<Vec<String>> {
        // A list of "hosts" AKA entries in the sysfs tree
        Ok(read_dir("/sys/class/fc_host/")?
            .into_iter()
            .map(|name| {
                name.map(|entry| entry.file_name().into_string().unwrap())
                    .unwrap()
            })
            .collect::<Vec<String>>())
    }
}

impl Default for FcPlugin {
    fn default() -> Self {
        let fc_data_points: [&'static str; 8] = [
            "fcp_input_megabytes",
            "fcp_input_requests",
            "fcp_output_megabytes",
            "fcp_output_requests",
            "fcp_packet_aborts",
            "invalid_crc_count",
            "invalid_tx_word_count",
            "link_failure_count",
        ];
        let endings: [&'static str; 4] = ["", ".mega", ".requests", ".other"];

        Self {
            // Those are never (outside recompile) going to change, so make it
            // a const. We are intereted in those datapoints for the fc_stats.
            // Entries here are filenames in
            // /sys/class/fc_host/HOST/statistics and are expected to show hex
            // numbers.
            fc_data_points,
            hosts: FcPlugin::get_hosts().expect("Could not read fc_hosts"),
            endings,
        }
    }
}

/// Parse a sysfs value from fc_host from hex to <<u128>>
macro_rules! parsedp {
    ($host:ident, $dp:ident) => {
        parse::<u128>(
            std::fs::read_to_string(
                Path::new("/sys/class/fc_host")
                    .join(&$host)
                    .join("statistics")
                    .join(&$dp),
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

impl MuninPlugin for FcPlugin {
    fn config<W: Write>(&self, handle: &mut BufWriter<W>) -> Result<()> {
        for hname in &self.hosts {
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
        Ok(())
    }

    fn acquire<W: Write>(
        &mut self,
        _handle: &mut BufWriter<W>,
        config: &Config,
        epoch: u64,
    ) -> Result<()> {
        // Look at each detected fc host
        for host in &self.hosts {
            // And gather the data we are interested in
            for dp in self.fc_data_points {
                // General cachefile for main graph
                let cachefile = Path::join(
                    &config.plugin_statedir,
                    format!("munin.fc_stats.value.{}", host),
                );
                let mut cachefd = openfd!(cachefile);

                match dp {
                    "fcp_input_megabytes" | "fcp_output_megabytes" => {
                        let mbcachefile = Path::join(
                            &config.plugin_statedir,
                            format!("munin.fc_stats.value.{}.mega", host),
                        );
                        let mut mbcachefd = openfd!(mbcachefile);
                        let data: u128 = parsedp!(host, dp);
                        wout!(cachefd, mbcachefd, host, dp, epoch, data);
                    }
                    "fcp_input_requests" | "fcp_output_requests" => {
                        let rqcachefile = Path::join(
                            &config.plugin_statedir,
                            format!("munin.fc_stats.value.{}.requests", host),
                        );
                        let mut rqcachefd = openfd!(rqcachefile);
                        let data: u128 = parsedp!(host, dp);
                        wout!(cachefd, rqcachefd, host, dp, epoch, data);
                    }
                    &_ => {
                        let ocachefile = Path::join(
                            &config.plugin_statedir,
                            format!("munin.fc_stats.value.{}.other", host),
                        );
                        let mut ocachefd = openfd!(ocachefile);
                        let data: u128 = parsedp!(host, dp);
                        wout!(cachefd, ocachefd, host, dp, epoch, data);
                    }
                }
            }
        }
        Ok(())
    }

    /// Reimplement fetch, as we use more than one file.
    fn fetch<W: Write>(&mut self, handle: &mut BufWriter<W>, config: &Config) -> Result<()> {
        for host in &self.hosts {
            for fname in self.endings {
                // Construct the filename
                let valfile = Path::join(
                    config.plugin_statedir.as_path(),
                    format!("munin.fc_stats.value.{}{}", host, fname),
                );
                trace!("Value file: {:?}", valfile);
                // And we need a tempfile, so we can mv the actual file over
                let tempfile = NamedTempFile::new_in(&config.plugin_statedir)?;
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
                            fname.replace('.', "")
                        )?;
                    }
                    &_ => {
                        writeln!(handle, "multigraph san_{0}", host)?;
                    }
                }
                // And ask io::copy to just take it all and shove it
                // into the handle (aka stdout)
                io::copy(&mut fetchfile, handle)?;
            }
        }
        Ok(())
    }
}

fn main() -> Result<()> {
    SimpleLogger::new().init().unwrap();
    info!("fc_stats started");

    // Set out config
    let mut config = Config::new_daemon(String::from("fc_stats"));
    // Fetchsize 64k is arbitary, but better than default 8k.
    config.fetch_size = 65535;
    // Config is big
    config.config_size = 16384;

    let mut fcstats = FcPlugin {
        ..Default::default()
    };

    // Get running
    fcstats.start(config)?;
    Ok(())
}
