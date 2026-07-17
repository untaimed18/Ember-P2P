use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, RwLock};
use tracing::{debug, info};

/// Shared GeoIP database. Starts empty so the network task can enter its
/// event loop before the MMDB is parsed; `fill` populates it later.
pub type GeoIpReader = Arc<RwLock<Option<maxminddb::Reader<Vec<u8>>>>>;

pub fn empty() -> GeoIpReader {
    Arc::new(RwLock::new(None))
}

/// Parse the MMDB from disk and install it into an existing shared handle.
/// Safe to call from `spawn_blocking`; lookups see `None` until this returns.
pub fn fill(target: &GeoIpReader, resource_dir: &Path) {
    let db_path = resource_dir
        .join("resources")
        .join("dbip-country-lite.mmdb");
    let path = if db_path.exists() {
        db_path
    } else {
        let alt = resource_dir.join("dbip-country-lite.mmdb");
        if !alt.exists() {
            debug!("GeoIP database not found at {:?}", db_path);
            return;
        }
        alt
    };
    match maxminddb::Reader::open_readfile(&path) {
        Ok(reader) => {
            info!("GeoIP database loaded from {:?}", path);
            if let Ok(mut slot) = target.write() {
                *slot = Some(reader);
            }
        }
        Err(e) => {
            debug!("Failed to load GeoIP database: {}", e);
        }
    }
}

#[derive(serde::Deserialize)]
struct CountryRecord {
    country: Option<CountryField>,
}

#[derive(serde::Deserialize)]
struct CountryField {
    iso_code: Option<String>,
}

pub fn lookup_country(reader: &GeoIpReader, ip: IpAddr) -> Option<String> {
    let guard = reader.read().ok()?;
    let r = guard.as_ref()?;
    // maxminddb 0.29: `lookup` returns a `LookupResult`; `decode` then yields
    // `Result<Option<T>, _>` (None when the IP isn't present). Treat any
    // lookup/decode error or a missing record as "no country".
    let result = r.lookup(ip).ok()?;
    let record: CountryRecord = result.decode().ok().flatten()?;
    record.country?.iso_code
}
