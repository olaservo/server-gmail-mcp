import fs from 'fs';
import path from 'path';
/** Split a raw env/string list on commas, semicolons or whitespace. */
function splitRaw(raw) {
    return raw.split(/[\s,;]+/).map(s => s.trim()).filter(Boolean);
}
/** Classify entries into exact addresses vs domains. */
export function parseAllowlistEntries(entries) {
    const addresses = new Set();
    const domains = new Set();
    for (const rawEntry of entries) {
        const entry = rawEntry.trim().toLowerCase();
        if (!entry)
            continue;
        if (entry.startsWith('@')) {
            // "@example.com" -> domain
            const d = entry.slice(1);
            if (d)
                domains.add(d);
        }
        else if (entry.includes('@')) {
            // "alice@example.com" -> exact address
            addresses.add(entry);
        }
        else if (entry.includes('.')) {
            // "example.com" -> bare domain
            domains.add(entry);
        }
        // anything else (no '@', no '.') is ignored as malformed
    }
    return { addresses, domains };
}
/** Read entries from a JSON allowlist file. Supports an array or an object. */
function readAllowlistFile(filePath) {
    try {
        if (!fs.existsSync(filePath))
            return [];
        const parsed = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
        if (Array.isArray(parsed)) {
            return parsed.map(String);
        }
        if (parsed && typeof parsed === 'object') {
            const out = [];
            if (Array.isArray(parsed.addresses))
                out.push(...parsed.addresses.map(String));
            if (Array.isArray(parsed.domains)) {
                // store domains with a leading '@' so the parser classifies them
                out.push(...parsed.domains.map((d) => (String(d).startsWith('@') ? String(d) : `@${d}`)));
            }
            if (Array.isArray(parsed.allowlist))
                out.push(...parsed.allowlist.map(String));
            return out;
        }
        return [];
    }
    catch {
        // A malformed file must not silently open the gate — treat as empty.
        return [];
    }
}
/**
 * Derive the per-account allowlist file path from the credentials path:
 *   .../credentials-johnny.json -> .../allowlist-johnny.json
 *   .../credentials.json        -> .../allowlist.json
 */
export function deriveAllowlistPath(credentialsPath) {
    const dir = path.dirname(credentialsPath);
    const base = path.basename(credentialsPath);
    const mapped = base.startsWith('credentials')
        ? base.replace(/^credentials/, 'allowlist')
        : 'allowlist.json';
    return path.join(dir, mapped);
}
/** Load and merge the allowlist from env + file. */
export function loadAllowlist(opts = {}) {
    const entries = [];
    if (opts.env)
        entries.push(...splitRaw(opts.env));
    const filePath = opts.allowlistPath
        || (opts.credentialsPath ? deriveAllowlistPath(opts.credentialsPath) : undefined);
    if (filePath)
        entries.push(...readAllowlistFile(filePath));
    const { addresses, domains } = parseAllowlistEntries(entries);
    return {
        addresses,
        domains,
        configured: addresses.size > 0 || domains.size > 0,
    };
}
/**
 * Extract the bare email address (lowercased) from a `From`-style header,
 * handling `Display Name <addr@x>`, `<addr@x>` and bare `addr@x`.
 */
export function extractAddress(fromHeader) {
    if (!fromHeader)
        return null;
    const angle = fromHeader.match(/<([^>]+)>/);
    const candidate = (angle ? angle[1] : fromHeader).trim().toLowerCase();
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(candidate) ? candidate : null;
}
/** True if the given `From` header's address is on the allowlist. */
export function isAllowed(fromHeader, allowlist) {
    if (!allowlist.configured)
        return false; // fail closed
    const addr = extractAddress(fromHeader);
    if (!addr)
        return false;
    if (allowlist.addresses.has(addr))
        return true;
    const domain = addr.split('@')[1];
    return !!domain && allowlist.domains.has(domain);
}
/**
 * Build a Gmail `from:(…)` query clause restricting results to allowlisted
 * senders, e.g. `from:(alice@x.com OR bob@y.com OR example.com)`.
 * Returns '' when nothing is configured.
 */
export function allowlistToFromQuery(allowlist) {
    const terms = [...allowlist.addresses, ...allowlist.domains];
    if (terms.length === 0)
        return '';
    return `from:(${terms.join(' OR ')})`;
}
/** Combine a caller's query with the allowlist from-clause (AND semantics). */
export function combineQuery(userQuery, fromQuery) {
    if (!fromQuery)
        return userQuery || '';
    if (!userQuery)
        return fromQuery;
    return `(${userQuery}) ${fromQuery}`;
}
/** Standard refusal text for a blocked read. */
export function blockedMessage(allowlist, context = 'This message') {
    if (!allowlist.configured) {
        return `Read blocked by allowlist policy: no trusted senders are configured. `
            + `Populate GMAIL_READ_ALLOWLIST (comma-separated addresses/domains) or the `
            + `allowlist JSON file next to this account's credentials, then retry. `
            + `(Fail-closed: reads are blocked until the allowlist is set.)`;
    }
    return `${context} was withheld: its sender is not on the read allowlist for this account.`;
}
