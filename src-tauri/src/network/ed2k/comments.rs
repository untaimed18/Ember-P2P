use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use tracing::debug;

pub const RATING_NOT_RATED: u8 = 0;
pub const RATING_FAKE: u8 = 1;
pub const RATING_POOR: u8 = 2;
pub const RATING_FAIR: u8 = 3;
pub const RATING_GOOD: u8 = 4;
pub const RATING_EXCELLENT: u8 = 5;

/// Unpack eMule `FT_FILERATING` / `TAG_FILERATING`. The rating is the low
/// byte (`1..=5`, `1` = fake). Packed DWORDs also carry a vote count in the
/// upper bytes; clamping the whole integer with `min(5)` mapped those to
/// five stars.
pub fn unpack_file_rating(value: u64) -> Option<u8> {
    let rating = (value & 0xFF) as u8;
    if rating == 0 {
        None
    } else {
        Some(rating.min(RATING_EXCELLENT))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileComment {
    pub user_name: String,
    pub rating: u8,
    pub comment: String,
    /// 0 = ed2k peer, 1 = KAD
    pub origin: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FileCommentInfo {
    pub our_rating: u8,
    pub our_comment: String,
    pub peer_comments: Vec<FileComment>,
}

const MAX_COMMENT_FILES: usize = 5000;
const MAX_COMMENTS_PER_FILE: usize = 100;

pub struct CommentManager {
    /// file_hash_hex -> comment info
    comments: HashMap<String, FileCommentInfo>,
}

impl CommentManager {
    pub fn new() -> Self {
        Self {
            comments: HashMap::new(),
        }
    }

    pub fn set_our_comment(&mut self, file_hash: &str, rating: u8, comment: String) {
        let entry = self.comments.entry(file_hash.to_string()).or_default();
        entry.our_rating = rating.min(RATING_EXCELLENT);
        entry.our_comment = comment;
        debug!("Set comment for {}: rating={}", file_hash, entry.our_rating);
    }

    pub fn add_peer_comment(
        &mut self,
        file_hash: &str,
        user_name: String,
        rating: u8,
        comment: String,
        origin: u8,
    ) {
        if !self.comments.contains_key(file_hash) && self.comments.len() >= MAX_COMMENT_FILES {
            return;
        }
        let user_name = crate::security::sanitize_remote_text(&user_name, 256);
        let comment = crate::security::sanitize_remote_text(&comment, 4096);
        if user_name.is_empty() && comment.is_empty() {
            return;
        }
        let entry = self.comments.entry(file_hash.to_string()).or_default();
        if let Some(existing) = entry
            .peer_comments
            .iter_mut()
            .find(|c| c.user_name == user_name)
        {
            existing.rating = rating.min(RATING_EXCELLENT);
            existing.comment = comment;
            existing.origin = origin;
            return;
        }
        if entry.peer_comments.len() >= MAX_COMMENTS_PER_FILE {
            return;
        }
        entry.peer_comments.push(FileComment {
            user_name,
            rating: rating.min(RATING_EXCELLENT),
            comment,
            origin,
        });
    }

    pub fn get_comments(&self, file_hash: &str) -> Option<&FileCommentInfo> {
        self.comments.get(file_hash)
    }

    pub fn get_our_comment(&self, file_hash: &str) -> (u8, &str) {
        match self.comments.get(file_hash) {
            Some(info) => (info.our_rating, &info.our_comment),
            None => (RATING_NOT_RATED, ""),
        }
    }

    pub fn average_rating(&self, file_hash: &str) -> f32 {
        let info = match self.comments.get(file_hash) {
            Some(i) => i,
            None => return 0.0,
        };
        let ratings: Vec<u8> = info
            .peer_comments
            .iter()
            .map(|c| c.rating)
            .filter(|&r| r > 0)
            .collect();
        if ratings.is_empty() {
            return 0.0;
        }
        ratings.iter().map(|&r| r as f32).sum::<f32>() / ratings.len() as f32
    }

    pub fn has_fake_rating(&self, file_hash: &str) -> bool {
        self.comments
            .get(file_hash)
            .map(|info| info.peer_comments.iter().any(|c| c.rating == RATING_FAKE))
            .unwrap_or(false)
    }

    /// Count of `(fake_votes, total_rated_votes)` among peer ratings for a
    /// file. Feeds the spam filter's community-verdict signal: a file the
    /// network has predominantly rated "fake" is a strong spam indicator.
    /// Only rated (rating > 0) peer comments are counted.
    pub fn fake_rating_stats(&self, file_hash: &str) -> (u32, u32) {
        match self.comments.get(file_hash) {
            Some(info) => {
                let mut fake = 0u32;
                let mut total = 0u32;
                if info.our_rating > 0 {
                    total += 1;
                    if info.our_rating == RATING_FAKE {
                        fake += 1;
                    }
                }
                for c in &info.peer_comments {
                    if c.rating > 0 {
                        total += 1;
                        if c.rating == RATING_FAKE {
                            fake += 1;
                        }
                    }
                }
                (fake, total)
            }
            None => (0, 0),
        }
    }

    pub fn load_from_db_rows(&mut self, rows: Vec<(String, u8, String)>) {
        for (hash, rating, comment) in rows {
            let entry = self.comments.entry(hash).or_default();
            entry.our_rating = rating;
            entry.our_comment = comment;
        }
    }
}

pub fn rating_name(rating: u8) -> &'static str {
    match rating {
        RATING_NOT_RATED => "Not Rated",
        RATING_FAKE => "Fake",
        RATING_POOR => "Poor",
        RATING_FAIR => "Fair",
        RATING_GOOD => "Good",
        RATING_EXCELLENT => "Excellent",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_user_replaces_previous_comment() {
        let mut cm = CommentManager::new();
        cm.add_peer_comment("aa", "alice".into(), RATING_FAKE, "one".into(), 0);
        cm.add_peer_comment("aa", "alice".into(), RATING_EXCELLENT, "two".into(), 0);
        let (fake, total) = cm.fake_rating_stats("aa");
        assert_eq!(total, 1);
        assert_eq!(fake, 0);
        assert_eq!(cm.get_comments("aa").unwrap().peer_comments.len(), 1);
    }

    #[test]
    fn peer_comment_strips_control_and_bidi() {
        let mut cm = CommentManager::new();
        cm.add_peer_comment(
            "aa",
            "al\u{202E}ice\0".into(),
            RATING_GOOD,
            "hi\nthere".into(),
            0,
        );
        let c = &cm.get_comments("aa").unwrap().peer_comments[0];
        assert!(!c.user_name.contains('\0'));
        assert!(!c.user_name.contains('\u{202E}'));
        assert!(!c.comment.contains('\n'));
    }

    #[test]
    fn our_fake_rating_counts() {
        let mut cm = CommentManager::new();
        cm.set_our_comment("bb", RATING_FAKE, "nope".into());
        let (fake, total) = cm.fake_rating_stats("bb");
        assert_eq!((fake, total), (1, 1));
    }

    #[test]
    fn unpack_file_rating_uses_low_byte() {
        assert_eq!(unpack_file_rating(0), None);
        assert_eq!(unpack_file_rating(1), Some(RATING_FAKE));
        assert_eq!(unpack_file_rating(4), Some(RATING_GOOD));
        assert_eq!(unpack_file_rating(5), Some(RATING_EXCELLENT));
        assert_eq!(unpack_file_rating(0x0000_0401), Some(RATING_FAKE));
        assert_eq!(unpack_file_rating(0x0000_0104), Some(RATING_GOOD));
        assert_eq!(unpack_file_rating(99), Some(RATING_EXCELLENT));
    }
}
