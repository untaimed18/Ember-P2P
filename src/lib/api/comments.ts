import { invoke } from '@tauri-apps/api/core';

export interface FileComment {
  user_name: string;
  rating: number;
  comment: string;
  origin: number;
}

export interface FileCommentInfo {
  our_rating: number;
  our_comment: string;
  peer_comments: FileComment[];
}

export async function setFileComment(fileHash: string, rating: number, comment: string): Promise<void> {
  return invoke('set_file_comment', { fileHash, rating, comment });
}

export async function getFileComments(fileHash: string): Promise<FileCommentInfo | null> {
  return invoke('get_file_comments', { fileHash });
}
