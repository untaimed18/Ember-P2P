import { describe, expect, it } from 'vitest';
import { FILE_TYPE_FILTERS, extensionFromPath, fileTypeKey } from './fileTypes';

describe('extensionFromPath', () => {
  it('takes the extension of the last segment on either separator', () => {
    expect(extensionFromPath('song.mp3')).toBe('mp3');
    expect(extensionFromPath('C:\\Music\\a.b\\song.FLAC')).toBe('FLAC');
    expect(extensionFromPath('/srv/archive.tar.gz')).toBe('gz');
  });

  it('returns nothing for no extension, a dotfile or a trailing dot', () => {
    expect(extensionFromPath('README')).toBe('');
    expect(extensionFromPath('.nfo')).toBe('');
    expect(extensionFromPath('name.')).toBe('');
    expect(extensionFromPath('dir.v2/README')).toBe('');
  });
});

describe('fileTypeKey', () => {
  it('buckets each category case-insensitively', () => {
    expect(fileTypeKey('MP3')).toBe('Audio');
    expect(fileTypeKey('mkv')).toBe('Video');
    expect(fileTypeKey('jpg')).toBe('Image');
    expect(fileTypeKey('7z')).toBe('Archive');
    expect(fileTypeKey('pdf')).toBe('Document');
    expect(fileTypeKey('iso')).toBe('CD/DVD');
  });

  it('leaves unknown extensions uncategorised', () => {
    expect(fileTypeKey('exe')).toBe('');
    expect(fileTypeKey('')).toBe('');
  });

  it('only ever returns a real filter option', () => {
    const options = new Set<string>(FILE_TYPE_FILTERS);
    for (const ext of ['mp3', 'mp4', 'png', 'zip', 'txt', 'bin']) {
      expect(options.has(fileTypeKey(ext))).toBe(true);
    }
  });
});
