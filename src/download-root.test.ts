import { describe, it, expect } from 'vitest';
import path from 'path';
import { loadDownloadRoot, resolveDownloadPath } from './download-root.js';

const root = path.resolve('/srv/gmail-downloads');

describe('loadDownloadRoot', () => {
    it('returns null when unset or blank', () => {
        expect(loadDownloadRoot(undefined)).toBeNull();
        expect(loadDownloadRoot('')).toBeNull();
        expect(loadDownloadRoot('   ')).toBeNull();
    });

    it('resolves to an absolute path', () => {
        expect(path.isAbsolute(loadDownloadRoot('downloads')!)).toBe(true);
        expect(loadDownloadRoot('  /srv/gmail-downloads  ')).toBe(root);
    });
});

describe('resolveDownloadPath with no root configured', () => {
    it('uses the requested path as-is', () => {
        expect(resolveDownloadPath('/tmp/out', null, process.cwd())).toBe(path.resolve('/tmp/out'));
    });

    it('falls back when no path is requested', () => {
        expect(resolveDownloadPath(undefined, null, '/tmp/fallback')).toBe(path.resolve('/tmp/fallback'));
    });
});

describe('resolveDownloadPath with a root configured', () => {
    it('interprets a relative path inside the root', () => {
        expect(resolveDownloadPath('invoices', root, process.cwd())).toBe(path.join(root, 'invoices'));
    });

    it('accepts an absolute path already inside the root', () => {
        const inside = path.join(root, 'nested', 'dir');
        expect(resolveDownloadPath(inside, root, process.cwd())).toBe(inside);
    });

    it('resolves to the root itself when nothing is requested', () => {
        expect(resolveDownloadPath(undefined, root, process.cwd())).toBe(root);
    });

    it('rejects an absolute path outside the root', () => {
        // The injection case: mail steers a download into a config directory.
        expect(() => resolveDownloadPath(path.resolve('/etc'), root, process.cwd())).toThrow(/GMAIL_DOWNLOAD_DIR/);
    });

    it('rejects traversal out of the root', () => {
        expect(() => resolveDownloadPath('../../etc', root, process.cwd())).toThrow(/GMAIL_DOWNLOAD_DIR/);
    });

    it('rejects a sibling directory that shares the root prefix', () => {
        // A naive startsWith(root) check would let this through.
        expect(() => resolveDownloadPath(root + '-evil', root, process.cwd())).toThrow(/GMAIL_DOWNLOAD_DIR/);
    });

    it('ignores the fallback entirely', () => {
        expect(resolveDownloadPath(undefined, root, '/tmp/elsewhere')).toBe(root);
    });
});
