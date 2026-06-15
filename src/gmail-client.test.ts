import { describe, it, expect } from 'vitest';
import { authResults, dmarcPassed } from './gmail-client.js';

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
        expect(dmarcPassed(payload('DMARC=PASS header.from=gmail.com'))).toBe(true);
    });

    it('does not match on substrings (dmarc=passing, dmarc=passerror)', () => {
        expect(dmarcPassed(payload('dmarc=passerror header.from=evil.com'))).toBe(false);
        expect(dmarcPassed(payload('dmarc=passing'))).toBe(false);
    });

    it('considers multiple Authentication-Results headers', () => {
        expect(dmarcPassed(payload(
            'relay.example.com; dmarc=none',
            'mx.google.com; dmarc=pass header.from=gmail.com'
        ))).toBe(true);
    });

    it('authResults joins and lowercases the header values', () => {
        expect(authResults(payload('DMARC=Pass', 'spf=Pass'))).toBe('dmarc=pass ; spf=pass');
    });
});
