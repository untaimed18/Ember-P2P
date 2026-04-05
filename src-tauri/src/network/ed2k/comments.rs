use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use tracing::debug;

pub const RATING_NOT_RATED: u8 = 0;
pub const RATING_FAKE: u8 = 1;
pub const RATING_POOR: u8 = 2;
pub const RATING_FAIR: u8 = 3;
pub const RATING_GOOD: u8 = 4;
pub const RATING_EXCELLENT: u8 = 5;

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

    pub fn add_peer_comment(&mut self, file_hash: &str, user_name: String, rating: u8, comment: String, origin: u8) {
        if !self.comments.contains_key(file_hash) && self.comments.len() >= MAX_COMMENT_FILES {
            return;
        }
        let user_name = if user_name.len() > 256 {
            user_name[..user_name.floor_char_boundary(256)].to_string()
        } else {
            user_name
        };
        let comment = if comment.len() > 4096 {
            comment[..comment.floor_char_boundary(4096)].to_string()
        } else {
            comment
        };
        let entry = self.comments.entry(file_hash.to_string()).or_default();
        if entry.peer_comments.iter().any(|c| c.user_name == user_name && c.comment == comment) {
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
        let ratings: Vec<u8> = info.peer_comments.iter()
            .map(|c| c.rating)
            .filter(|&r| r > 0)
            .collect();
        if ratings.is_empty() {
            return 0.0;
        }
        ratings.iter().map(|&r| r as f32).sum::<f32>() / ratings.len() as f32
    }

    pub fn has_fake_rating(&self, file_hash: &str) -> bool {
        self.comments.get(file_hash)
            .map(|info| info.peer_comments.iter().any(|c| c.rating == RATING_FAKE))
            .unwrap_or(false)
    }

    pub fn all_comments(&self) -> &HashMap<String, FileCommentInfo> {
        &self.comments
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
