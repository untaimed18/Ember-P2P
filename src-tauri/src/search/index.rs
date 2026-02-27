use std::collections::HashMap;

use crate::types::{FileInfo, SearchResult};

pub struct LocalIndex {
    files: Vec<FileInfo>,
    hash_map: HashMap<String, usize>,
    name_tokens: HashMap<String, Vec<usize>>,
}

impl LocalIndex {
    pub fn new() -> Self {
        Self {
            files: Vec::new(),
            hash_map: HashMap::new(),
            name_tokens: HashMap::new(),
        }
    }

    pub fn add_files(&mut self, files: Vec<FileInfo>) {
        for file in files {
            self.add_file(file);
        }
    }

    pub fn add_file(&mut self, file: FileInfo) {
        let idx = self.files.len();
        self.hash_map.insert(file.hash.clone(), idx);

        let name_lower = file.name.to_lowercase();
        for token in tokenize(&name_lower) {
            self.name_tokens
                .entry(token)
                .or_default()
                .push(idx);
        }

        self.files.push(file);
    }

    pub fn search(&self, query: &str) -> Vec<SearchResult> {
        let query_lower = query.to_lowercase();
        let query_tokens = tokenize(&query_lower);

        if query_tokens.is_empty() {
            return Vec::new();
        }

        let mut score_map: HashMap<usize, u32> = HashMap::new();

        for token in &query_tokens {
            for (indexed_token, indices) in &self.name_tokens {
                if indexed_token.contains(token.as_str()) {
                    for &idx in indices {
                        *score_map.entry(idx).or_insert(0) += 1;
                    }
                }
            }
        }

        let mut results: Vec<(usize, u32)> = score_map.into_iter().collect();
        results.sort_by(|a, b| b.1.cmp(&a.1));

        results
            .into_iter()
            .take(100)
            .filter_map(|(idx, score)| {
                self.files.get(idx).map(|file| SearchResult {
                    file: file.clone(),
                    peer_id: "local".to_string(),
                    peer_name: "You".to_string(),
                    availability: score,
                    file_type: infer_file_type(&file.extension),
                    source_addresses: vec!["local".to_string()],
                    rating: None,
                    comment: None,
                })
            })
            .collect()
    }

    pub fn get_by_hash(&self, hash: &str) -> Option<&FileInfo> {
        self.hash_map
            .get(hash)
            .and_then(|&idx| self.files.get(idx))
    }

    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    pub fn all_files(&self) -> &[FileInfo] {
        &self.files
    }

    pub fn remove_files_by_path_prefix(&mut self, prefix: &str) {
        self.files.retain(|f| !f.path.starts_with(prefix));
        self.rebuild_indices();
    }

    pub fn remove_file_by_hash(&mut self, hash: &str) -> Option<FileInfo> {
        if let Some(&idx) = self.hash_map.get(hash) {
            if idx < self.files.len() {
                let removed = self.files.remove(idx);
                self.rebuild_indices();
                return Some(removed);
            }
        }
        None
    }

    pub fn set_file_priority(&mut self, hash: &str, priority: &str) -> bool {
        if let Some(&idx) = self.hash_map.get(hash) {
            if let Some(file) = self.files.get_mut(idx) {
                file.priority = priority.to_string();
                return true;
            }
        }
        false
    }

    fn rebuild_indices(&mut self) {
        self.hash_map.clear();
        self.name_tokens.clear();
        for (idx, file) in self.files.iter().enumerate() {
            self.hash_map.insert(file.hash.clone(), idx);
            let name_lower = file.name.to_lowercase();
            for token in tokenize(&name_lower) {
                self.name_tokens.entry(token).or_default().push(idx);
            }
        }
    }
}

fn tokenize(s: &str) -> Vec<String> {
    s.split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(|t| t.to_string())
        .collect()
}

pub fn infer_file_type(extension: &str) -> String {
    match extension.to_lowercase().as_str() {
        "mp3" | "ogg" | "wav" | "wma" | "flac" | "aac" | "m4a" | "ape" | "mpc" | "opus" => "Audio".into(),
        "avi" | "mkv" | "mp4" | "wmv" | "mov" | "mpg" | "mpeg" | "flv" | "m4v" | "rmvb"
        | "rm" | "divx" | "ogm" | "vob" | "webm" | "ts" => "Video".into(),
        "jpg" | "jpeg" | "png" | "gif" | "bmp" | "tiff" | "tif" | "svg" | "webp" | "ico"
        | "psd" => "Image".into(),
        "exe" | "msi" | "apk" | "dmg" | "app" | "deb" | "rpm" | "bat" | "cmd" | "com"
        | "scr" => "Pro".into(),
        "doc" | "docx" | "pdf" | "txt" | "rtf" | "xls" | "xlsx" | "ppt" | "pptx" | "odt"
        | "ods" | "odp" | "epub" | "djvu" | "chm" | "lit" | "mobi" | "azw" | "cbr"
        | "cbz" => "Doc".into(),
        "zip" | "rar" | "7z" | "tar" | "gz" | "bz2" | "xz" | "ace" | "cab" | "lzh"
        | "arj" => "Arc".into(),
        "iso" | "bin" | "cue" | "img" | "nrg" | "mdf" | "mds" | "ccd" | "sub" => "Iso".into(),
        _ => String::new(),
    }
}
