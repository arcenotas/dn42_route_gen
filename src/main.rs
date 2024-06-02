use std::{
    env,
    fs::{self, DirEntry},
    io,
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, Result};
use serde::Serialize;

const CACHE_EXPIRY: u64 = 7 * 24 * 60 * 60;

#[derive(Serialize)]
struct Metadata {
    counts: usize,
    generated: u64,
    valid: u64,
}

#[derive(Serialize)]
struct ROA {
    prefix: String,
    #[serde(rename = "maxLength")]
    max_length: u8,
    asn: String,
}

#[derive(Serialize)]
struct Routes {
    metadata: Metadata,
    roas: Vec<ROA>,
}

struct CIDR {
    ip: IpAddr,
    netmask: u8,
}

impl CIDR {
    fn from_str(s: &str) -> Result<CIDR> {
        let parts: Vec<_> = s.split("/").collect();
        if parts.len() != 2 {
            return Err(anyhow!("invalid CIDR: {s}"));
        }

        let ip: IpAddr = parts[0].parse()?;
        let netmask: u8 = parts[1].parse()?;

        Ok(CIDR { ip, netmask })
    }

    fn contains(&self, ip: &IpAddr) -> bool {
        match (&self.ip, ip) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                let a = u32::from(*a);
                let b = u32::from(*b);
                a >> (32 - self.netmask) == b >> (32 - self.netmask)
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                let a = u128::from(*a);
                let b = u128::from(*b);
                a >> (128 - self.netmask) == b >> (128 - self.netmask)
            }
            _ => false,
        }
    }
}

fn main() -> Result<()> {
    let args: Vec<_> = env::args().collect();

    if args.len() != 3 {
        return Err(anyhow!("Usage: {} registry route.json", args[0]));
    }

    let mut filters = vec![];

    process_filter(&format!("{}/data/filter.txt", args[1]), &mut filters)?;
    process_filter(&format!("{}/data/filter6.txt", args[1]), &mut filters)?;

    let mut roas = vec![];

    process_directory(&format!("{}/data/route", args[1]), &mut roas, &filters)?;
    process_directory(&format!("{}/data/route6", args[1]), &mut roas, &filters)?;

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let expire = now + CACHE_EXPIRY;

    let metadata = Metadata {
        counts: roas.len(),
        generated: now,
        valid: expire,
    };

    let routes = Routes { metadata, roas };

    let output = serde_json::to_string(&routes)?;
    fs::write(&args[2], output)?;

    Ok(())
}

fn process_filter(path: &str, filters: &mut Vec<(CIDR, bool, u8, u8)>) -> Result<()> {
    let process_line = |line: &str| {
        let first = line.chars().next()?;
        if first < '0' || first > '9' {
            return None;
        }

        let mut line = line.split_whitespace().skip(1);

        let allow = match line.next()? {
            "deny" => false,
            "permit" => true,
            _ => return None,
        };

        let cidr = CIDR::from_str(line.next()?).ok()?;
        let min: u8 = line.next()?.parse().ok()?;
        let max: u8 = line.next()?.parse().ok()?;

        Some((cidr, allow, min, max))
    };

    fs::read_to_string(path)?
        .split("\n")
        .filter_map(|line| process_line(line))
        .for_each(|(cidr, allow, min, max)| filters.push((cidr, allow, min, max)));

    Ok(())
}

fn process_directory(
    path: &str,
    roas: &mut Vec<ROA>,
    filters: &Vec<(CIDR, bool, u8, u8)>,
) -> Result<()> {
    fs::read_dir(path)?
        .into_iter()
        .filter_map(|file| process_entry(file, &filters).ok())
        .for_each(|roa| roas.extend(roa));

    Ok(())
}

fn process_entry(
    file: Result<DirEntry, io::Error>,
    filters: &Vec<(CIDR, bool, u8, u8)>,
) -> Result<Vec<ROA>> {
    let file = fs::read_to_string(file?.path())?;

    let mut prefix: Option<String> = None;
    let mut asn = vec![];
    let mut max_length: Option<u8> = None;

    let lines: Vec<_> = file.split("\n").collect();
    for line in lines {
        if line.chars().next().filter(|c| c.is_whitespace()).is_some() {
            continue;
        }

        let line = line.to_ascii_lowercase();
        let line: Vec<_> = line.split_whitespace().collect();
        if line.len() < 2 {
            continue;
        }

        match line[0] {
            "route:" | "route6:" => prefix = Some(line[1].to_owned()),
            "origin:" => asn.push(line[1].to_ascii_uppercase()),
            "max-length:" => max_length = Some(line[1].parse()?),
            _ => continue,
        }
    }

    let prefix = prefix.ok_or(anyhow!("no route specified"))?;
    let prefix_parts: Vec<_> = prefix.split("/").collect();

    let addr: IpAddr = prefix_parts[0].parse()?;
    let netmask: u8 = prefix_parts[1].parse()?;

    let mut filter: Option<(u8, u8)> = None;

    for f in filters {
        if !f.0.contains(&addr) {
            continue;
        }

        if !f.1 {
            return Ok(vec![]);
        }

        filter = Some((f.2, f.3));
        break;
    }

    let filter = filter.ok_or(anyhow!("IP {addr} is in an invalid range"))?;

    let max_length = match max_length {
        Some(max_length) => {
            if max_length > filter.1 {
                filter.1
            } else if max_length < filter.0 {
                filter.0
            } else {
                max_length
            }
        }
        None => filter.1,
    };

    if netmask > max_length {
        return Ok(vec![]);
    }

    let roas = asn
        .iter()
        .map(|asn| ROA {
            prefix: prefix.clone(),
            max_length,
            asn: asn.to_owned(),
        })
        .collect();

    Ok(roas)
}
