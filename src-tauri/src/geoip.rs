use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use tracing::{info, warn};

pub type GeoIpReader = Arc<Option<maxminddb::Reader<Vec<u8>>>>;

pub fn load(resource_dir: &Path) -> GeoIpReader {
    let db_path = resource_dir.join("resources").join("dbip-country-lite.mmdb");
    if !db_path.exists() {
        let alt = resource_dir.join("dbip-country-lite.mmdb");
        if alt.exists() {
            return load_from(&alt);
        }
        warn!("GeoIP database not found at {:?}", db_path);
        return Arc::new(None);
    }
    load_from(&db_path)
}

fn load_from(path: &Path) -> GeoIpReader {
    match maxminddb::Reader::open_readfile(path) {
        Ok(reader) => {
            info!("GeoIP database loaded from {:?}", path);
            Arc::new(Some(reader))
        }
        Err(e) => {
            warn!("Failed to load GeoIP database: {}", e);
            Arc::new(None)
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
    let r = reader.as_ref().as_ref()?;
    let record: CountryRecord = r.lookup(ip).ok()?;
    record.country?.iso_code
}
