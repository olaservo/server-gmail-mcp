/**
 * Tests for the read-allowlist policy (Feature 2).
 */

import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import {
    parseAllowlistEntries,
    extractAddress,
    isAllowed,
    allowlistToFromQuery,
    combineQuery,
    deriveAllowlistPath,
    loadAllowlist,
    blockedMessage,
    Allowlist,
} from './allowlist.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function makeAllowlist(entries: string[]): Allowlist {
    const { addresses, domains } = parseAllowlistEntries(entries);
    return { addresses, domains, configured: addresses.size > 0 || domains.size > 0 };
}

describe('parseAllowlistEntries', () => {
    it('classifies addresses, @domains and bare domains', () => {
        const { addresses, domains } = parseAllowlistEntries([
            'Alice@Example.com', '@trusted.org', 'corp.net', 'garbage', '',
        ]);
        expect(addresses.has('alice@example.com')).toBe(true);
        expect(domains.has('trusted.org')).toBe(true);
        expect(domains.has('corp.net')).toBe(true);
        // 'garbage' (no @, no .) is ignored
        expect(addresses.size).toBe(1);
        expect(domains.size).toBe(2);
    });
});

describe('extractAddress', () => {
    it('parses display-name with angle brackets', () => {
        expect(extractAddress('John Doe <john@x.com>')).toBe('john@x.com');
    });
    it('parses quoted display-name', () => {
        expect(extractAddress('"Doe, John" <John@X.COM>')).toBe('john@x.com');
    });
    it('parses bare address', () => {
        expect(extractAddress('jane@y.com')).toBe('jane@y.com');
    });
    it('returns null for non-addresses', () => {
        expect(extractAddress('Mailer Daemon')).toBeNull();
        expect(extractAddress('')).toBeNull();
    });
});

describe('isAllowed', () => {
    const allowlist = makeAllowlist(['alice@example.com', '@trusted.org']);

    it('allows exact address match (case-insensitive)', () => {
        expect(isAllowed('Alice <ALICE@example.com>', allowlist)).toBe(true);
    });
    it('allows domain match', () => {
        expect(isAllowed('Bob <bob@trusted.org>', allowlist)).toBe(true);
    });
    it('blocks off-list senders', () => {
        expect(isAllowed('Eve <eve@evil.com>', allowlist)).toBe(false);
    });
    it('blocks when address cannot be parsed', () => {
        expect(isAllowed('not an address', allowlist)).toBe(false);
    });
    it('fails closed when allowlist is empty/unconfigured', () => {
        const empty = makeAllowlist([]);
        expect(empty.configured).toBe(false);
        expect(isAllowed('alice@example.com', empty)).toBe(false);
    });
});

describe('allowlistToFromQuery + combineQuery', () => {
    it('builds a from-clause from addresses and domains', () => {
        const q = allowlistToFromQuery(makeAllowlist(['alice@example.com', '@trusted.org']));
        expect(q).toMatch(/^from:\(/);
        expect(q).toContain('alice@example.com');
        expect(q).toContain('trusted.org');
    });
    it('returns empty clause when nothing configured', () => {
        expect(allowlistToFromQuery(makeAllowlist([]))).toBe('');
    });
    it('combines user query with the from-clause (AND semantics)', () => {
        const combined = combineQuery('subject:invoice', 'from:(alice@example.com)');
        expect(combined).toBe('(subject:invoice) from:(alice@example.com)');
    });
    it('returns user query unchanged when from-clause is empty', () => {
        expect(combineQuery('is:unread', '')).toBe('is:unread');
    });
    it('returns from-clause when user query is empty', () => {
        expect(combineQuery('', 'from:(a@b.com)')).toBe('from:(a@b.com)');
    });
});

describe('deriveAllowlistPath', () => {
    it('maps credentials-<acct>.json to allowlist-<acct>.json', () => {
        const p = deriveAllowlistPath(path.join('/home/u/.gmail-mcp', 'credentials-johnny.json'));
        expect(path.basename(p)).toBe('allowlist-johnny.json');
    });
    it('maps plain credentials.json to allowlist.json', () => {
        const p = deriveAllowlistPath(path.join('/home/u/.gmail-mcp', 'credentials.json'));
        expect(path.basename(p)).toBe('allowlist.json');
    });
});

describe('loadAllowlist', () => {
    it('loads from env (comma/space/semicolon separated)', () => {
        const al = loadAllowlist({ env: 'alice@example.com, @trusted.org; bob@x.com' });
        expect(al.configured).toBe(true);
        expect(isAllowed('alice@example.com', al)).toBe(true);
        expect(isAllowed('bob@x.com', al)).toBe(true);
        expect(isAllowed('x@trusted.org', al)).toBe(true);
    });

    it('is unconfigured (fail-closed) when no sources given', () => {
        expect(loadAllowlist({}).configured).toBe(false);
    });

    it('loads and merges a JSON file (array form)', () => {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'allowlist-'));
        const file = path.join(dir, 'allowlist-test.json');
        fs.writeFileSync(file, JSON.stringify(['carol@example.com', '@partner.io']));
        try {
            const al = loadAllowlist({ allowlistPath: file });
            expect(al.configured).toBe(true);
            expect(isAllowed('carol@example.com', al)).toBe(true);
            expect(isAllowed('x@partner.io', al)).toBe(true);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('loads a JSON file (object form with addresses/domains)', () => {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'allowlist-'));
        const file = path.join(dir, 'allowlist-test.json');
        fs.writeFileSync(file, JSON.stringify({ addresses: ['dan@example.com'], domains: ['partner.io'] }));
        try {
            const al = loadAllowlist({ allowlistPath: file });
            expect(isAllowed('dan@example.com', al)).toBe(true);
            expect(isAllowed('x@partner.io', al)).toBe(true);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('treats a malformed JSON file as empty (does not open the gate)', () => {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'allowlist-'));
        const file = path.join(dir, 'allowlist-test.json');
        fs.writeFileSync(file, '{ this is not json');
        try {
            expect(loadAllowlist({ allowlistPath: file }).configured).toBe(false);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });
});

describe('blockedMessage', () => {
    it('gives populate-the-list guidance when unconfigured', () => {
        const msg = blockedMessage(makeAllowlist([]));
        expect(msg).toContain('GMAIL_READ_ALLOWLIST');
        expect(msg.toLowerCase()).toContain('fail-closed');
    });
    it('explains the sender is off-list when configured', () => {
        const msg = blockedMessage(makeAllowlist(['a@b.com']), 'This email');
        expect(msg).toContain('not on the read allowlist');
    });
});

describe('Source verification: read paths are gated', () => {
    const indexSource = fs.readFileSync(path.join(__dirname, 'index.ts'), 'utf-8');

    it('read_email is guarded', () => {
        expect(indexSource).toContain("readGuard(from, 'This email')");
    });
    it('search_emails injects the from-clause and post-filters', () => {
        expect(indexSource).toContain('allowlistToFromQuery(readAllowlist)');
        expect(indexSource).toContain('allResults.filter(r => isAllowed(r.from, readAllowlist))');
    });
    it('download_attachment resolves and gates the sender', () => {
        expect(indexSource).toContain("readGuard(attFrom, 'This attachment')");
    });
    it('thread tools filter by sender', () => {
        expect(indexSource).toContain('messagesOutput.filter(m => isAllowed(m.from, readAllowlist))');
        expect(indexSource).toContain('isAllowed(t.latestMessage.from, readAllowlist)');
    });
    it('the account self-address is always trusted', () => {
        expect(indexSource).toContain('readAllowlist.addresses.add(profile.data.emailAddress.toLowerCase())');
    });
});
