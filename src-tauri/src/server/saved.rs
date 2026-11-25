//! What the browser saves from emberd that is not in the Library, which
//! `/api/file` serves: a followed feed's file, a friend's attachment, a file a
//! room member sent, and a collection made in the Library.
//!
//! The command that finds one checks it as its desktop twin checks what it
//! opens, and leaves it here under an id the page fetches at once, from
//! `/api/saved/<id>`. An id is sent once and lapses unfetched after
//! [`KEEP`], so a page cannot hold a file open on the server.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use rand::RngCore as _;

use crate::commands::errors::coded_ctx;

/// How long an offer waits for the page, which fetches it as soon as it has
/// the id.
const KEEP: Duration = Duration::from_secs(120);
/// Offers held at once; past it the oldest goes. Each is fetched the moment
/// its id reaches the page, so this many waiting means saves clicked faster
/// than the browser starts them.
const MAX_HELD: usize = 64;

/// What is to be saved: an opened file and its length, or bytes made for it.
pub(crate) enum Content {
    File(std::fs::File, u64),
    Bytes(Vec<u8>),
}

struct Offer {
    content: Content,
    name: String,
    at: Instant,
    /// Order of arrival, which two offers in one tick of the clock share.
    seq: u64,
}

fn offers() -> &'static parking_lot::Mutex<HashMap<String, Offer>> {
    static OFFERS: std::sync::OnceLock<parking_lot::Mutex<HashMap<String, Offer>>> = std::sync::OnceLock::new();
    OFFERS.get_or_init(Default::default)
}

/// Leave `content` to be saved as `name`; the id the page fetches it by.
pub(crate) fn offer(content: Content, name: &str) -> String {
    let mut id = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut id);
    let id = hex::encode(id);
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut held = offers().lock();
    held.retain(|_, offer| offer.at.elapsed() < KEEP);
    while held.len() >= MAX_HELD {
        let Some(oldest) = held.iter().min_by_key(|(_, offer)| offer.seq).map(|(id, _)| id.clone()) else {
            break;
        };
        held.remove(&oldest);
    }
    held.insert(
        id.clone(),
        Offer {
            content,
            name: super::uploads::safe_name(name),
            at: Instant::now(),
            seq,
        },
    );
    id
}

/// Open the file at `path`, which the caller has checked, and offer it.
pub(crate) async fn offer_file(path: PathBuf, name: &str) -> Result<String, String> {
    let opened = tokio::task::spawn_blocking(move || {
        let file = std::fs::File::open(&path)?;
        let length = file.metadata()?.len();
        Ok::<_, std::io::Error>((file, length))
    })
    .await
    .map_err(|e| coded_ctx("server_file_unavailable", "That file could not be read", e))?
    .map_err(|e| coded_ctx("server_file_unavailable", "That file could not be read", e))?;
    Ok(offer(Content::File(opened.0, opened.1), name))
}

/// The offer `id` names, taken: each is sent once.
pub(crate) fn take(id: &str) -> Option<(Content, String)> {
    let offer = offers().lock().remove(id)?;
    (offer.at.elapsed() < KEEP).then_some((offer.content, offer.name))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One test, since the offers are process-wide.
    #[test]
    fn an_offer_is_sent_once_under_a_safe_name_and_few_are_held() {
        let id = offer(Content::Bytes(b"list".to_vec()), "../My list.emulecollection");
        assert_eq!(id.len(), 32);
        let Some((Content::Bytes(bytes), name)) = take(&id) else {
            panic!("the offer is there");
        };
        assert_eq!(bytes, b"list");
        assert_eq!(name, "My list.emulecollection", "a name made safe to save");
        assert!(take(&id).is_none(), "and gone once taken");
        assert!(take("not an id").is_none());

        let ids: Vec<String> = (0..MAX_HELD + 4).map(|n| offer(Content::Bytes(vec![n as u8]), "f")).collect();
        assert!(offers().lock().len() <= MAX_HELD);
        assert!(take(&ids[0]).is_none(), "the oldest went");
        assert!(take(ids.last().unwrap()).is_some(), "the newest is kept");
        for id in &ids {
            take(id);
        }
    }
}
