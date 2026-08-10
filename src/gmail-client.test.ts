import { describe, it, expect } from 'vitest';
import { authResults, dmarcPassed, timingSafeEqualStr } from './gmail-client.js';

// Build a minimal message payload with the given Authentication-Results header(s).
const payload = (...authValues: string[]): any => ({
    headers: authValues.map(value => ({ name: 'Authentication-Results', value })),
});

describe('dmarcPassed (spoof defense)', () => {
    it('passes when the receiving server reports dmarc=pass', () => {
        expect(dmarcPassed(payload(
            'mx.google.com; spf=pass smtp.mailfrom=alice@gmail.com; dkim=pass header.i=@gmail.com; dmarc=pass (p=NONE) header.from=gmail.com'
        ))).toBe(true);
    });

    it('fails when dmarc=fail (forged From domain)', () => {
        expect(dmarcPassed(payload(
            'mx.google.com; spf=softfail; dkim=none; dmarc=fail (p=REJECT) header.from=gmail.com'
        ))).toBe(false);
    });

    it('fails closed when there is no Authentication-Results header', () => {
        expect(dmarcPassed(payload())).toBe(false);
        expect(dmarcPassed(undefined)).toBe(false);
        expect(dmarcPassed({} as any)).toBe(false);
    });

    it('is case-insensitive (phones/relays may uppercase)', () => {
        expect(dmarcPassed(payload('mx.google.com; DMARC=PASS header.from=gmail.com'))).toBe(true);
    });

    it('does not match on substrings (dmarc=passing, dmarc=passerror)', () => {
        expect(dmarcPassed(payload('mx.google.com; dmarc=passerror header.from=evil.com'))).toBe(false);
        expect(dmarcPassed(payload('mx.google.com; dmarc=passing'))).toBe(false);
    });

    it('only trusts the verdict stamped by the receiving server (mx.google.com)', () => {
        expect(dmarcPassed(payload(
            'relay.example.com; dmarc=none',
            'mx.google.com; dmarc=pass header.from=gmail.com'
        ))).toBe(true);
    });

    it('ignores a forged dmarc=pass stamped with a non-Gmail authserv-id', () => {
        // Attacker injects their own Authentication-Results header; Gmail's real verdict failed.
        expect(dmarcPassed(payload(
            'evil.example.com; dmarc=pass header.from=trusted.com',
            'mx.google.com; spf=fail; dmarc=fail header.from=trusted.com'
        ))).toBe(false);
        // A pass under an untrusted authserv-id, with no Gmail verdict at all, is not enough.
        expect(dmarcPassed(payload('relay.example.com; dmarc=pass'))).toBe(false);
    });

    it('authResults joins and lowercases the header values', () => {
        expect(authResults(payload('DMARC=Pass', 'spf=Pass'))).toBe('dmarc=pass ; spf=pass');
    });
});

// The OAuth `state` comparison. A loopback redirect URI is an unauthenticated
// endpoint for as long as the listener is up, so this predicate is what stops a
// callback we did not initiate from being exchanged for tokens.
describe('timingSafeEqualStr', () => {
    const state = 'EViYa9hZj5C5UY3Lg2h3zm67jcuBSML3w6RhrTuPSyM';

    it('accepts the exact value', () => {
        expect(timingSafeEqualStr(state, state)).toBe(true);
    });

    it('rejects a missing state — the login-CSRF case', () => {
        // URLSearchParams.get() returns null when the parameter is absent.
        expect(timingSafeEqualStr(null, state)).toBe(false);
        expect(timingSafeEqualStr(undefined, state)).toBe(false);
        expect(timingSafeEqualStr('', state)).toBe(false);
    });

    it('rejects a same-length mismatch', () => {
        expect(timingSafeEqualStr('A'.repeat(state.length), state)).toBe(false);
    });

    it('rejects a prefix and a suffix rather than throwing on length', () => {
        // crypto.timingSafeEqual throws on unequal lengths; the guard must catch it.
        expect(timingSafeEqualStr(state.slice(0, -1), state)).toBe(false);
        expect(timingSafeEqualStr(state + 'x', state)).toBe(false);
    });

    it('rejects a non-string', () => {
        expect(timingSafeEqualStr(42 as any, state)).toBe(false);
        expect(timingSafeEqualStr({} as any, state)).toBe(false);
    });

    it('is case-sensitive', () => {
        expect(timingSafeEqualStr(state.toLowerCase(), state)).toBe(false);
    });
});
