/**
 * Shared Gmail auth + MIME parsing core.
 *
 * Extracted from index.ts so multiple entrypoints (the MCP tool server in
 * index.ts and the one-way channel in channel.ts) can share the same OAuth
 * bootstrap, cached-token handling, and message parsing without duplicating it.
 *
 * Auth state (`oauth2Client`, `authorizedScopes`) is module-private; callers
 * reach it through `getGmail()` and `getAuthorizedScopes()` after awaiting
 * `loadCredentials()`.
 */

import { google } from 'googleapis';
import { OAuth2Client } from 'google-auth-library';
import fs from 'fs';
import path from 'path';
import http from 'http';
import open from 'open';
import os from 'os';
import { DEFAULT_SCOPES, scopeNamesToUrls } from "./scopes.js";
import { EmailAttachment } from "./email-export.js";

// Configuration paths
export const CONFIG_DIR = path.join(os.homedir(), '.gmail-mcp');
export const OAUTH_PATH = process.env.GMAIL_OAUTH_PATH || path.join(CONFIG_DIR, 'gcp-oauth.keys.json');
export const CREDENTIALS_PATH = process.env.GMAIL_CREDENTIALS_PATH || path.join(CONFIG_DIR, 'credentials.json');

// Type definitions for Gmail API responses
export interface GmailMessagePart {
    partId?: string;
    mimeType?: string;
    filename?: string;
    headers?: Array<{
        name: string;
        value: string;
    }>;
    body?: {
        attachmentId?: string;
        size?: number;
        data?: string;
    };
    parts?: GmailMessagePart[];
}

export interface EmailContent {
    text: string;
    html: string;
}

// OAuth2 configuration (module-private state)
let oauth2Client: OAuth2Client;
let authorizedScopes: string[] = DEFAULT_SCOPES;

/** Returns the authorized scopes loaded from the credentials file (or defaults). */
export function getAuthorizedScopes(): string[] {
    return authorizedScopes;
}

/** Returns a Gmail API client bound to the loaded OAuth credentials. Call loadCredentials() first. */
export function getGmail() {
    return google.gmail({ version: 'v1', auth: oauth2Client });
}

/**
 * Recursively extract email body content from MIME message parts
 * Handles complex email structures with nested parts
 */
export function extractEmailContent(messagePart: GmailMessagePart): EmailContent {
    // Initialize containers for different content types
    let textContent = '';
    let htmlContent = '';

    // If the part has a body with data, process it based on MIME type
    if (messagePart.body && messagePart.body.data) {
        const content = Buffer.from(messagePart.body.data, 'base64').toString('utf8');

        // Store content based on its MIME type
        if (messagePart.mimeType === 'text/plain') {
            textContent = content;
        } else if (messagePart.mimeType === 'text/html') {
            htmlContent = content;
        }
    }

    // If the part has nested parts, recursively process them
    if (messagePart.parts && messagePart.parts.length > 0) {
        for (const part of messagePart.parts) {
            const { text, html } = extractEmailContent(part);
            if (text) textContent += text;
            if (html) htmlContent += html;
        }
    }

    // Return both plain text and HTML content
    return { text: textContent, html: htmlContent };
}

/**
 * Extract common headers from Gmail message payload
 */
export function extractHeaders(payload: any): { subject: string; from: string; to: string; date: string; rfcMessageId: string; inReplyTo: string; references: string } {
    const headers = payload?.headers || [];
    const getHeader = (name: string) =>
        headers.find((h: any) => h.name?.toLowerCase() === name.toLowerCase())?.value || "";
    return {
        subject: getHeader("subject"),
        from: getHeader("from"),
        to: getHeader("to"),
        date: getHeader("date"),
        rfcMessageId: getHeader("message-id"),
        inReplyTo: getHeader("in-reply-to"),
        references: getHeader("references"),
    };
}

/**
 * Extract attachments from Gmail message payload
 */
export function extractAttachments(payload: GmailMessagePart): EmailAttachment[] {
    const attachments: EmailAttachment[] = [];

    function processAttachmentParts(part: GmailMessagePart) {
        if (part.body && part.body.attachmentId) {
            attachments.push({
                id: part.body.attachmentId,
                filename: part.filename || `attachment-${part.body.attachmentId}`,
                mimeType: part.mimeType || "application/octet-stream",
                size: part.body.size || 0,
            });
        }
        if (part.parts) {
            part.parts.forEach((subpart: GmailMessagePart) => processAttachmentParts(subpart));
        }
    }

    processAttachmentParts(payload);
    return attachments;
}

/** All `Authentication-Results` header values for a message, lowercased and joined. */
export function authResults(payload: GmailMessagePart | undefined): string {
    const headers = payload?.headers ?? [];
    return headers
        .filter(h => h.name?.toLowerCase() === "authentication-results")
        .map(h => (h.value ?? "").toLowerCase())
        .join(" ; ");
}

// The receiving server's authserv-id. Only an `Authentication-Results` header
// stamped with this id is trustworthy: per RFC 7601 §5 the receiver strips inbound
// A-R headers bearing its OWN id before adding its verdict, so an attacker cannot
// forge one with this id — but they CAN add a header under any other id. Gmail
// (incl. Workspace) uses "mx.google.com"; override only if a different MTA delivers.
const TRUSTED_AUTHSERV_ID = (process.env.GMAIL_AUTHSERV_ID || "mx.google.com").toLowerCase();

/**
 * True if the receiving server's verdict shows DMARC passed. DMARC requires the
 * authenticated SPF/DKIM domain to align with the `From:` header domain, so a pass
 * means the From address wasn't spoofed.
 *
 * Only the `Authentication-Results` header whose authserv-id matches the trusted
 * receiver is considered — a `dmarc=pass` an attacker injected under a different
 * authserv-id is ignored. Absence of a trusted passing verdict is a failure
 * (fail closed).
 */
export function dmarcPassed(payload: GmailMessagePart | undefined): boolean {
    const headers = payload?.headers ?? [];
    for (const h of headers) {
        if (h.name?.toLowerCase() !== "authentication-results") continue;
        const value = (h.value ?? "").trim().toLowerCase();
        // authserv-id is the first token, before an optional version and the first ';'
        // (RFC 7601 §2.2). Ignore headers not stamped by the trusted receiver.
        const authservId = value.split(";")[0].trim().split(/\s+/)[0];
        if (authservId !== TRUSTED_AUTHSERV_ID) continue;
        if (/\bdmarc=pass\b/.test(value)) return true;
    }
    return false;
}

export async function loadCredentials() {
    try {
        // Create config directory if it doesn't exist
        if (!process.env.GMAIL_OAUTH_PATH && !process.env.GMAIL_CREDENTIALS_PATH && !fs.existsSync(CONFIG_DIR)) {
            fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
        }

        // Check for OAuth keys in current directory first, then in config directory
        const localOAuthPath = path.join(process.cwd(), 'gcp-oauth.keys.json');

        if (fs.existsSync(localOAuthPath)) {
            // If found in current directory, copy to config directory
            fs.copyFileSync(localOAuthPath, OAUTH_PATH);
            // stderr, not stdout: loadCredentials() runs on the server path, where
            // stdout is the JSON-RPC channel and MUST carry nothing but MCP messages
            // (stdio transport spec). One stray line here breaks the client's parser.
            console.error('OAuth keys found in current directory, copied to global config.');
        }

        if (!fs.existsSync(OAUTH_PATH)) {
            console.error('Error: OAuth keys file not found. Please place gcp-oauth.keys.json in current directory or', CONFIG_DIR);
            process.exit(1);
        }

        const keysContent = JSON.parse(fs.readFileSync(OAUTH_PATH, 'utf8'));
        const keys = keysContent.installed || keysContent.web;

        if (!keys) {
            console.error('Error: Invalid OAuth keys file format. File should contain either "installed" or "web" credentials.');
            process.exit(1);
        }

        // Parse callback URL from args (must be a URL, not a flag)
        // Supports: node index.js auth https://example.com/callback
        // Or: node index.js auth --scopes=gmail.readonly (uses default callback)
        const callbackArg = process.argv.find(arg =>
            arg.startsWith('http://') || arg.startsWith('https://')
        );
        const callback = callbackArg || "http://localhost:3000/oauth2callback";

        oauth2Client = new OAuth2Client(
            keys.client_id,
            keys.client_secret,
            callback
        );

        if (fs.existsSync(CREDENTIALS_PATH)) {
            const credentials = JSON.parse(fs.readFileSync(CREDENTIALS_PATH, 'utf8'));

            // Credentials file structure (v1.2.0+):
            //   { "tokens": { access_token, refresh_token, ... }, "scopes": ["gmail.readonly", ...] }
            //
            // Legacy structure (pre-v1.2.0):
            //   { access_token, refresh_token, ... }
            //
            // We support both formats for backwards compatibility. Users with legacy
            // credentials will get DEFAULT_SCOPES (full access) until they re-authenticate.
            const tokens = credentials.tokens || credentials;
            oauth2Client.setCredentials(tokens);

            if (credentials.scopes) {
                authorizedScopes = credentials.scopes;
            }
        }
    } catch (error) {
        console.error('Error loading credentials:', error);
        process.exit(1);
    }
}

export async function authenticate(scopes: string[]) {
    const server = http.createServer();
    server.listen(3000, '127.0.0.1');

    // Convert shorthand scope names (e.g., "gmail.readonly") to full Google API URLs
    const scopeUrls = scopeNamesToUrls(scopes);

    return new Promise<void>((resolve, reject) => {
        const authUrl = oauth2Client.generateAuthUrl({
            access_type: 'offline',
            scope: scopeUrls,
        });

        console.log('Requesting scopes:', scopes.join(', '));
        console.log('Please visit this URL to authenticate:', authUrl);
        open(authUrl);

        server.on('request', async (req, res) => {
            if (!req.url?.startsWith('/oauth2callback')) return;

            const url = new URL(req.url, 'http://localhost:3000');
            const code = url.searchParams.get('code');

            if (!code) {
                res.writeHead(400);
                res.end('No code provided');
                reject(new Error('No code provided'));
                return;
            }

            try {
                const { tokens } = await oauth2Client.getToken(code);
                oauth2Client.setCredentials(tokens);

                // Store both tokens and authorized scopes for runtime filtering
                const credentials = { tokens, scopes };
                fs.writeFileSync(CREDENTIALS_PATH, JSON.stringify(credentials, null, 2), { mode: 0o600 });

                res.writeHead(200);
                res.end('Authentication successful! You can close this window.');
                console.log('Credentials saved with scopes:', scopes.join(', '));
                server.close();
                resolve();
            } catch (error) {
                res.writeHead(500);
                res.end('Authentication failed');
                reject(error);
            }
        });
    });
}
