#!/usr/bin/env node

import { serveStdio } from "@modelcontextprotocol/server/stdio";
import { Server } from "@modelcontextprotocol/server";
import type { CallToolRequest, CallToolResult, ListToolsResult } from "@modelcontextprotocol/server";
import fs from 'fs';
import path from 'path';
import { createRequire } from 'node:module';
import {createEmailMessage, createEmailWithNodemailer} from "./utl.js";
import { createLabel, updateLabel, deleteLabel, listLabels, findLabelByName, getOrCreateLabel, GmailLabel } from "./label-manager.js";
import { createFilter, listFilters, getFilter, deleteFilter, filterTemplates, GmailFilterCriteria, GmailFilterAction } from "./filter-manager.js";
import { parseEmailAddresses, filterOutEmail, addRePrefix, buildReferencesHeader, buildReplyAllRecipients } from "./reply-all-helpers.js";
import { DEFAULT_SCOPES, parseScopes, validateScopes, hasScope, getAvailableScopeNames } from "./scopes.js";
import { toolDefinitions, toMcpTools, getToolByName, isReadOnlyTool, SendEmailSchema, ReadEmailSchema, SearchEmailsSchema, ModifyEmailSchema, DeleteEmailSchema, BatchModifyEmailsSchema, BatchDeleteEmailsSchema, CreateLabelSchema, UpdateLabelSchema, DeleteLabelSchema, GetOrCreateLabelSchema, CreateFilterSchema, GetFilterSchema, DeleteFilterSchema, CreateFilterFromTemplateSchema, DownloadAttachmentSchema, ReplyAllSchema, GetThreadSchema, ListInboxThreadsSchema, GetInboxWithThreadsSchema, DownloadEmailSchema } from "./tools.js";
import { gmailMessageToJson, emailToTxt, emailToHtml, EmailAttachment } from "./email-export.js";
import { loadAllowlist, isAllowed, allowlistToFromQuery, combineQuery, blockedMessage, Allowlist } from "./allowlist.js";
import { CREDENTIALS_PATH, loadCredentials, authenticate, getGmail, getAuthorizedScopes, extractEmailContent, extractHeaders, extractAttachments, dmarcPassed, GmailMessagePart, EmailContent } from "./gmail-client.js";

// Gmail OAuth bootstrap, config paths (CREDENTIALS_PATH), response types
// (GmailMessagePart/EmailContent), and MIME parsing helpers now live in
// ./gmail-client.ts, shared with the channel entrypoint (channel.ts).

// Implementation.version the server reports to clients. Read from package.json
// rather than hardcoded so it can never drift from the published version.
// Resolves the same from src/ (dev) and dist/ (build): both sit one level down.
const { version: SERVER_VERSION } = createRequire(import.meta.url)('../package.json') as { version: string };

// Main function
async function main() {
    await loadCredentials();

    if (process.argv[2] === 'auth') {
        // Parse --scopes flag from CLI arguments
        // Usage: node dist/index.js auth --scopes=<scope1,scope2,...>
        // Example: node dist/index.js auth --scopes=gmail.readonly
        // Example: node dist/index.js auth --scopes=gmail.readonly,gmail.settings.basic
        const scopesArg = process.argv.find(arg => arg.startsWith('--scopes='));
        let scopes = DEFAULT_SCOPES;

        if (scopesArg) {
            const scopesValue = scopesArg.slice('--scopes='.length);
            scopes = parseScopes(scopesValue);
            const validation = validateScopes(scopes);

            if (!validation.valid) {
                console.error('Error: Invalid scope(s):', validation.invalid.join(', '));
                console.error('Available scopes:', getAvailableScopeNames().join(', '));
                process.exit(1);
            }
        } else {
            console.log('No --scopes flag specified, using defaults:', DEFAULT_SCOPES.join(', '));
            console.log('Tip: Use --scopes=gmail.readonly for read-only access');
            console.log('Available scopes:', getAvailableScopeNames().join(', '));
        }

        await authenticate(scopes);
        console.log('Authentication completed successfully');
        process.exit(0);
    }

    // Initialize Gmail API
    const gmail = getGmail();

    // Load the read-allowlist policy (Feature 2) for this account.
    const readAllowlist: Allowlist = loadAllowlist({
        env: process.env.GMAIL_READ_ALLOWLIST,
        allowlistPath: process.env.GMAIL_ALLOWLIST_PATH,
        credentialsPath: CREDENTIALS_PATH,
    });
    // The account's own address is always trusted (so own sent messages in a
    // thread are never filtered out). Does not flip `configured` — if nothing was
    // configured, reads still fail closed.
    try {
        const profile = await gmail.users.getProfile({ userId: 'me' });
        if (profile.data.emailAddress) {
            readAllowlist.addresses.add(profile.data.emailAddress.toLowerCase());
        }
    } catch (e: any) {
        console.warn(`Warning: could not fetch profile for self-allowlisting: ${e?.message}`);
    }
    if (!readAllowlist.configured) {
        console.warn(
            'Read allowlist is not configured — all read/search results are blocked (fail-closed). '
            + 'Set GMAIL_READ_ALLOWLIST or an allowlist JSON file beside the credentials.'
        );
    }

    // Write tools (send, draft, reply, delete, modify, label/filter management) are disabled
    // by default. The server exposes only read-only tools unless explicitly opted in. This is
    // layered on top of the OAuth-scope filter and works with existing credentials.
    const writeToolsEnabled = /^(1|true|yes)$/i.test((process.env.GMAIL_ENABLE_WRITE_TOOLS || '').trim());
    if (!writeToolsEnabled) {
        console.warn(
            'Write tools are disabled (read-only mode). '
            + 'Set GMAIL_ENABLE_WRITE_TOOLS=true to enable send/draft/delete/label/filter tools.'
        );
    }

    /**
     * Read guard: returns a refusal content object if reading mail from
     * `fromHeader` is not permitted by the allowlist, or null if allowed.
     */
    // Spoof-resistance: the allowlist matches the (forgeable) From header. When
    // GMAIL_REQUIRE_AUTH is on, additionally require that the message passed DMARC,
    // which verifies the From domain is authentic. Fail closed if the verdict is absent.
    const requireAuth = /^(1|true|yes)$/i.test((process.env.GMAIL_REQUIRE_AUTH || '').trim());

    const readGuard = (fromHeader: string, context?: string, payload?: GmailMessagePart) => {
        if (!isAllowed(fromHeader, readAllowlist)) {
            return { content: [{ type: "text" as const, text: blockedMessage(readAllowlist, context) }] };
        }
        if (requireAuth && !dmarcPassed(payload)) {
            return { content: [{ type: "text" as const, text: `${context ?? 'This email'} could not be verified (DMARC did not pass) and may be spoofed, so it was withheld.` }] };
        }
        return null;
    };

    // Tool handlers, declared once and registered on every server instance
    // serveStdio builds (see buildServer below).
    // Filter available tools based on authorized scopes
    const listToolsHandler = async (): Promise<ListToolsResult> => {
        const availableTools = toolDefinitions.filter(tool =>
            hasScope(getAuthorizedScopes(), tool.scopes) &&
            (writeToolsEnabled || isReadOnlyTool(tool))
        );
        return { tools: toMcpTools(availableTools) };
    };

    const callToolHandler = async (request: CallToolRequest): Promise<CallToolResult> => {
        const { name, arguments: args } = request.params;

        // Verify the tool is authorized for the current scopes
        // This guards against direct tool calls that bypass ListTools
        const toolDef = getToolByName(name);
        if (!toolDef || !hasScope(getAuthorizedScopes(), toolDef.scopes)) {
            return {
                isError: true,
                content: [{
                    type: "text",
                    text: `Error: Tool "${name}" is not available. You may need to re-authenticate with additional scopes.`,
                }],
            };
        }

        // Guard against direct calls to write tools while in read-only (default) mode.
        if (!writeToolsEnabled && !isReadOnlyTool(toolDef)) {
            return {
                isError: true,
                content: [{
                    type: "text",
                    text: `Error: Tool "${name}" is a write operation and is disabled. Set GMAIL_ENABLE_WRITE_TOOLS=true to enable write tools.`,
                }],
            };
        }

        async function handleEmailAction(action: "send" | "draft", validatedArgs: any): Promise<CallToolResult> {
            let message: string;

            try {
                // An explicit messageIdHeader (RFC2822 Message-ID of the parent) overrides
                // automatic resolution: use it as In-Reply-To, and seed References if absent.
                if (validatedArgs.messageIdHeader && !validatedArgs.inReplyTo) {
                    validatedArgs.inReplyTo = validatedArgs.messageIdHeader;
                    if (!validatedArgs.references) {
                        validatedArgs.references = validatedArgs.messageIdHeader;
                    }
                }

                // Auto-resolve threading headers when threadId is provided but inReplyTo is missing
                if (validatedArgs.threadId && !validatedArgs.inReplyTo) {
                    try {
                        const threadResponse = await gmail.users.threads.get({
                            userId: 'me',
                            id: validatedArgs.threadId,
                            format: 'metadata',
                            metadataHeaders: ['Message-ID'],
                        });

                        const threadMessages = threadResponse.data.messages || [];
                        if (threadMessages.length > 0) {
                            // Collect all Message-ID values for the References chain
                            const allMessageIds: string[] = [];
                            for (const msg of threadMessages) {
                                const msgHeaders = msg.payload?.headers || [];
                                const messageIdHeader = msgHeaders.find(
                                    (h) => h.name?.toLowerCase() === 'message-id'
                                );
                                if (messageIdHeader?.value) {
                                    allMessageIds.push(messageIdHeader.value);
                                }
                            }

                            // Last message's Message-ID becomes In-Reply-To
                            const lastMessage = threadMessages[threadMessages.length - 1];
                            const lastHeaders = lastMessage.payload?.headers || [];
                            const lastMessageId = lastHeaders.find(
                                (h) => h.name?.toLowerCase() === 'message-id'
                            )?.value;

                            if (lastMessageId) {
                                validatedArgs.inReplyTo = lastMessageId;
                            }
                            if (allMessageIds.length > 0) {
                                validatedArgs.references = allMessageIds.join(' ');
                            }
                        }
                    } catch (threadError: any) {
                        console.warn(`Warning: Could not fetch thread ${validatedArgs.threadId} for header resolution: ${threadError.message}`);
                        // Continue without threading headers - degraded but not broken
                    }
                }

                // Check if we have attachments
                if (validatedArgs.attachments && validatedArgs.attachments.length > 0) {
                    // Use Nodemailer to create properly formatted RFC822 message
                    message = await createEmailWithNodemailer(validatedArgs);
                    
                    if (action === "send") {
                        const encodedMessage = Buffer.from(message).toString('base64')
                            .replace(/\+/g, '-')
                            .replace(/\//g, '_')
                            .replace(/=+$/, '');

                        const result = await gmail.users.messages.send({
                            userId: 'me',
                            requestBody: {
                                raw: encodedMessage,
                                ...(validatedArgs.threadId && { threadId: validatedArgs.threadId })
                            }
                        });
                        
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: `Email sent successfully with ID: ${result.data.id}`,
                                },
                            ],
                        };
                    } else {
                        // For drafts with attachments, use the raw message
                        const encodedMessage = Buffer.from(message).toString('base64')
                            .replace(/\+/g, '-')
                            .replace(/\//g, '_')
                            .replace(/=+$/, '');
                        
                        const messageRequest = {
                            raw: encodedMessage,
                            ...(validatedArgs.threadId && { threadId: validatedArgs.threadId })
                        };
                        
                        const response = await gmail.users.drafts.create({
                            userId: 'me',
                            requestBody: {
                                message: messageRequest,
                            },
                        });
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: `Email draft created successfully with ID: ${response.data.id}`,
                                },
                            ],
                        };
                    }
                } else {
                    // For emails without attachments, use the existing simple method
                    message = createEmailMessage(validatedArgs);
                    
                    const encodedMessage = Buffer.from(message).toString('base64')
                        .replace(/\+/g, '-')
                        .replace(/\//g, '_')
                        .replace(/=+$/, '');

                    // Define the type for messageRequest
                    interface GmailMessageRequest {
                        raw: string;
                        threadId?: string;
                    }

                    const messageRequest: GmailMessageRequest = {
                        raw: encodedMessage,
                    };

                    // Add threadId if specified
                    if (validatedArgs.threadId) {
                        messageRequest.threadId = validatedArgs.threadId;
                    }

                    if (action === "send") {
                        const response = await gmail.users.messages.send({
                            userId: 'me',
                            requestBody: messageRequest,
                        });
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: `Email sent successfully with ID: ${response.data.id}`,
                                },
                            ],
                        };
                    } else {
                        const response = await gmail.users.drafts.create({
                            userId: 'me',
                            requestBody: {
                                message: messageRequest,
                        },
                        });
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: `Email draft created successfully with ID: ${response.data.id}`,
                                },
                            ],
                        };
                    }
                }
            } catch (error: any) {
                // Log attachment-related errors for debugging
                if (validatedArgs.attachments && validatedArgs.attachments.length > 0) {
                    console.error(`Failed to send email with ${validatedArgs.attachments.length} attachments:`, error.message);
                }
                throw error;
            }
        }

        // Helper function to process operations in batches
        async function processBatches<T, U>(
            items: T[],
            batchSize: number,
            processFn: (batch: T[]) => Promise<U[]>
        ): Promise<{ successes: U[], failures: { item: T, error: Error }[] }> {
            const successes: U[] = [];
            const failures: { item: T, error: Error }[] = [];
            
            // Process in batches
            for (let i = 0; i < items.length; i += batchSize) {
                const batch = items.slice(i, i + batchSize);
                try {
                    const results = await processFn(batch);
                    successes.push(...results);
                } catch (error) {
                    // If batch fails, try individual items
                    for (const item of batch) {
                        try {
                            const result = await processFn([item]);
                            successes.push(...result);
                        } catch (itemError) {
                            failures.push({ item, error: itemError as Error });
                        }
                    }
                }
            }
            
            return { successes, failures };
        }

        try {
            switch (name) {
                case "send_email":
                case "draft_email": {
                    const validatedArgs = SendEmailSchema.parse(args);
                    const action = name === "send_email" ? "send" : "draft";
                    return await handleEmailAction(action, validatedArgs);
                }

                case "read_email": {
                    const validatedArgs = ReadEmailSchema.parse(args);
                    const response = await gmail.users.messages.get({
                        userId: 'me',
                        id: validatedArgs.messageId,
                        format: 'full',
                    });

                    const { subject, from, to, date, rfcMessageId, inReplyTo, references } = extractHeaders(response.data.payload);

                    // Allowlist guard: never surface mail from untrusted senders.
                    const readBlock = readGuard(from, 'This email', response.data.payload as GmailMessagePart);
                    if (readBlock) return readBlock;

                    const threadId = response.data.threadId || '';
                    const { text, html } = extractEmailContent(response.data.payload as GmailMessagePart || {});
                    const attachments = extractAttachments(response.data.payload as GmailMessagePart);

                    // Use plain text content if available, otherwise use HTML content
                    const body = text || html || '';
                    const contentTypeNote = !text && html ?
                        '[Note: This email is HTML-formatted. Plain text version not available.]\n\n' : '';

                    // Add attachment info to output if any are present
                    const attachmentInfo = attachments.length > 0 ?
                        `\n\nAttachments (${attachments.length}):\n` +
                        attachments.map(a => `- ${a.filename} (${a.mimeType}, ${Math.round(a.size/1024)} KB, ID: ${a.id})`).join('\n') : '';

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Thread ID: ${threadId}\nMessage-ID: ${rfcMessageId}${inReplyTo ? `\nIn-Reply-To: ${inReplyTo}` : ''}${references ? `\nReferences: ${references}` : ''}\nSubject: ${subject}\nFrom: ${from}\nTo: ${to}\nDate: ${date}\n\n${contentTypeNote}${body}${attachmentInfo}`,
                            },
                        ],
                    };
                }

                case "search_emails": {
                    const validatedArgs = SearchEmailsSchema.parse(args);

                    // Allowlist guard: fail closed if nothing is configured.
                    if (!readAllowlist.configured) {
                        return { content: [{ type: "text", text: blockedMessage(readAllowlist) }] };
                    }
                    // Restrict the query to allowlisted senders up front (defence in depth;
                    // we also post-filter below so nothing off-list can ever be returned).
                    const guardedQuery = combineQuery(validatedArgs.query, allowlistToFromQuery(readAllowlist));

                    const response = await gmail.users.messages.list({
                        userId: 'me',
                        q: guardedQuery,
                        maxResults: validatedArgs.maxResults || 10,
                    });

                    const messages = response.data.messages || [];
                    const allResults = await Promise.all(
                        messages.map(async (msg) => {
                            const detail = await gmail.users.messages.get({
                                userId: 'me',
                                id: msg.id!,
                                format: 'metadata',
                                metadataHeaders: ['Subject', 'From', 'Date', 'Authentication-Results'],
                            });
                            const headers = detail.data.payload?.headers || [];
                            return {
                                id: msg.id,
                                subject: headers.find(h => h.name === 'Subject')?.value || '',
                                from: headers.find(h => h.name === 'From')?.value || '',
                                date: headers.find(h => h.name === 'Date')?.value || '',
                                authed: dmarcPassed(detail.data.payload as GmailMessagePart),
                            };
                        })
                    );
                    // Post-filter: drop anything whose sender is not allowlisted (and, when
                    // GMAIL_REQUIRE_AUTH is on, anything that didn't pass DMARC).
                    const results = allResults.filter(r => isAllowed(r.from, readAllowlist) && (!requireAuth || r.authed));

                    return {
                        content: [
                            {
                                type: "text",
                                text: results.map(r =>
                                    `ID: ${r.id}\nSubject: ${r.subject}\nFrom: ${r.from}\nDate: ${r.date}\n`
                                ).join('\n'),
                            },
                        ],
                    };
                }

                case "download_email": {
                    const validatedArgs = DownloadEmailSchema.parse(args);
                    const { messageId, savePath, format } = validatedArgs;

                    try {
                        // Ensure save directory exists
                        if (!fs.existsSync(savePath)) {
                            fs.mkdirSync(savePath, { recursive: true });
                        }

                        // Always fetch full message for metadata (needed for attachments list)
                        const fullResponse = await gmail.users.messages.get({
                            userId: "me",
                            id: messageId,
                            format: "full",
                        });

                        const { subject, from, date } = extractHeaders(fullResponse.data.payload);

                        // Allowlist guard: do not write untrusted mail to disk.
                        const dlBlock = readGuard(from, 'This email', fullResponse.data.payload as GmailMessagePart);
                        if (dlBlock) return dlBlock;

                        const attachments = extractAttachments(fullResponse.data.payload as GmailMessagePart);

                        let content: string;

                        if (format === "eml") {
                            // For EML format, fetch raw RFC822 message
                            const rawResponse = await gmail.users.messages.get({
                                userId: "me",
                                id: messageId,
                                format: "raw",
                            });
                            content = Buffer.from(rawResponse.data.raw || "", "base64url").toString("utf-8");
                        } else {
                            // Extract email content for json/txt/html
                            const emailContent = extractEmailContent(fullResponse.data.payload as GmailMessagePart || {});

                            if (format === "json") {
                                const jsonData = gmailMessageToJson(fullResponse.data, emailContent, attachments);
                                content = JSON.stringify(jsonData, null, 2);
                            } else if (format === "txt") {
                                content = emailToTxt(fullResponse.data, emailContent, attachments);
                            } else {
                                // html - just return the raw HTML content
                                content = emailToHtml(emailContent);
                            }
                        }

                        // Write file
                        const filename = `${messageId}.${format}`;
                        const fullPath = path.join(savePath, filename);
                        fs.writeFileSync(fullPath, content, "utf-8");
                        const stats = fs.statSync(fullPath);

                        // Return metadata with attachments
                        const result = {
                            status: "saved",
                            path: fullPath,
                            size: stats.size,
                            messageId,
                            subject,
                            from,
                            date,
                            attachments,
                        };

                        return {
                            content: [
                                {
                                    type: "text",
                                    text: JSON.stringify(result, null, 2),
                                },
                            ],
                        };
                    } catch (error: any) {
                        return {
                            isError: true,
                            content: [
                                {
                                    type: "text",
                                    text: `Failed to download email: ${error.message}`,
                                },
                            ],
                        };
                    }
                }

                // Updated implementation for the modify_email handler
                case "modify_email": {
                    const validatedArgs = ModifyEmailSchema.parse(args);
                    
                    // Prepare request body
                    const requestBody: any = {};
                    
                    if (validatedArgs.labelIds) {
                        requestBody.addLabelIds = validatedArgs.labelIds;
                    }
                    
                    if (validatedArgs.addLabelIds) {
                        requestBody.addLabelIds = validatedArgs.addLabelIds;
                    }
                    
                    if (validatedArgs.removeLabelIds) {
                        requestBody.removeLabelIds = validatedArgs.removeLabelIds;
                    }
                    
                    await gmail.users.messages.modify({
                        userId: 'me',
                        id: validatedArgs.messageId,
                        requestBody: requestBody,
                    });

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Email ${validatedArgs.messageId} labels updated successfully`,
                            },
                        ],
                    };
                }

                case "delete_email": {
                    const validatedArgs = DeleteEmailSchema.parse(args);
                    await gmail.users.messages.delete({
                        userId: 'me',
                        id: validatedArgs.messageId,
                    });

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Email ${validatedArgs.messageId} deleted successfully`,
                            },
                        ],
                    };
                }

                case "list_email_labels": {
                    const labelResults = await listLabels(gmail);
                    const systemLabels = labelResults.system;
                    const userLabels = labelResults.user;

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Found ${labelResults.count.total} labels (${labelResults.count.system} system, ${labelResults.count.user} user):\n\n` +
                                    "System Labels:\n" +
                                    systemLabels.map((l: GmailLabel) => `ID: ${l.id}\nName: ${l.name}\n`).join('\n') +
                                    "\nUser Labels:\n" +
                                    userLabels.map((l: GmailLabel) => `ID: ${l.id}\nName: ${l.name}\n`).join('\n')
                            },
                        ],
                    };
                }

                case "batch_modify_emails": {
                    const validatedArgs = BatchModifyEmailsSchema.parse(args);
                    const messageIds = validatedArgs.messageIds;
                    const batchSize = validatedArgs.batchSize || 50;
                    
                    // Prepare request body
                    const requestBody: any = {};
                    
                    if (validatedArgs.addLabelIds) {
                        requestBody.addLabelIds = validatedArgs.addLabelIds;
                    }
                    
                    if (validatedArgs.removeLabelIds) {
                        requestBody.removeLabelIds = validatedArgs.removeLabelIds;
                    }

                    // Process messages in batches
                    const { successes, failures } = await processBatches(
                        messageIds,
                        batchSize,
                        async (batch) => {
                            const results = await Promise.all(
                                batch.map(async (messageId) => {
                                    const result = await gmail.users.messages.modify({
                                        userId: 'me',
                                        id: messageId,
                                        requestBody: requestBody,
                                    });
                                    return { messageId, success: true };
                                })
                            );
                            return results;
                        }
                    );

                    // Generate summary of the operation
                    const successCount = successes.length;
                    const failureCount = failures.length;
                    
                    let resultText = `Batch label modification complete.\n`;
                    resultText += `Successfully processed: ${successCount} messages\n`;
                    
                    if (failureCount > 0) {
                        resultText += `Failed to process: ${failureCount} messages\n\n`;
                        resultText += `Failed message IDs:\n`;
                        resultText += failures.map(f => `- ${(f.item as string).substring(0, 16)}... (${f.error.message})`).join('\n');
                    }

                    return {
                        content: [
                            {
                                type: "text",
                                text: resultText,
                            },
                        ],
                    };
                }

                case "batch_delete_emails": {
                    const validatedArgs = BatchDeleteEmailsSchema.parse(args);
                    const messageIds = validatedArgs.messageIds;
                    const batchSize = validatedArgs.batchSize || 50;

                    // Process messages in batches
                    const { successes, failures } = await processBatches(
                        messageIds,
                        batchSize,
                        async (batch) => {
                            const results = await Promise.all(
                                batch.map(async (messageId) => {
                                    await gmail.users.messages.delete({
                                        userId: 'me',
                                        id: messageId,
                                    });
                                    return { messageId, success: true };
                                })
                            );
                            return results;
                        }
                    );

                    // Generate summary of the operation
                    const successCount = successes.length;
                    const failureCount = failures.length;
                    
                    let resultText = `Batch delete operation complete.\n`;
                    resultText += `Successfully deleted: ${successCount} messages\n`;
                    
                    if (failureCount > 0) {
                        resultText += `Failed to delete: ${failureCount} messages\n\n`;
                        resultText += `Failed message IDs:\n`;
                        resultText += failures.map(f => `- ${(f.item as string).substring(0, 16)}... (${f.error.message})`).join('\n');
                    }

                    return {
                        content: [
                            {
                                type: "text",
                                text: resultText,
                            },
                        ],
                    };
                }

                // New label management handlers
                case "create_label": {
                    const validatedArgs = CreateLabelSchema.parse(args);
                    const result = await createLabel(gmail, validatedArgs.name, {
                        messageListVisibility: validatedArgs.messageListVisibility,
                        labelListVisibility: validatedArgs.labelListVisibility,
                    });

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Label created successfully:\nID: ${result.id}\nName: ${result.name}\nType: ${result.type}`,
                            },
                        ],
                    };
                }

                case "update_label": {
                    const validatedArgs = UpdateLabelSchema.parse(args);
                    
                    // Prepare request body with only the fields that were provided
                    const updates: any = {};
                    if (validatedArgs.name) updates.name = validatedArgs.name;
                    if (validatedArgs.messageListVisibility) updates.messageListVisibility = validatedArgs.messageListVisibility;
                    if (validatedArgs.labelListVisibility) updates.labelListVisibility = validatedArgs.labelListVisibility;
                    
                    const result = await updateLabel(gmail, validatedArgs.id, updates);

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Label updated successfully:\nID: ${result.id}\nName: ${result.name}\nType: ${result.type}`,
                            },
                        ],
                    };
                }

                case "delete_label": {
                    const validatedArgs = DeleteLabelSchema.parse(args);
                    const result = await deleteLabel(gmail, validatedArgs.id);

                    return {
                        content: [
                            {
                                type: "text",
                                text: result.message,
                            },
                        ],
                    };
                }

                case "get_or_create_label": {
                    const validatedArgs = GetOrCreateLabelSchema.parse(args);
                    const result = await getOrCreateLabel(gmail, validatedArgs.name, {
                        messageListVisibility: validatedArgs.messageListVisibility,
                        labelListVisibility: validatedArgs.labelListVisibility,
                    });

                    const action = result.type === 'user' && result.name === validatedArgs.name ? 'found existing' : 'created new';
                    
                    return {
                        content: [
                            {
                                type: "text",
                                text: `Successfully ${action} label:\nID: ${result.id}\nName: ${result.name}\nType: ${result.type}`,
                            },
                        ],
                    };
                }


                // Filter management handlers
                case "create_filter": {
                    const validatedArgs = CreateFilterSchema.parse(args);
                    const result = await createFilter(gmail, validatedArgs.criteria, validatedArgs.action);

                    // Format criteria for display
                    const criteriaText = Object.entries(validatedArgs.criteria)
                        .filter(([_, value]) => value !== undefined)
                        .map(([key, value]) => `${key}: ${value}`)
                        .join(', ');

                    // Format actions for display
                    const actionText = Object.entries(validatedArgs.action)
                        .filter(([_, value]) => value !== undefined && (Array.isArray(value) ? value.length > 0 : true))
                        .map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join(', ') : value}`)
                        .join(', ');

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Filter created successfully:\nID: ${result.id}\nCriteria: ${criteriaText}\nActions: ${actionText}`,
                            },
                        ],
                    };
                }

                case "list_filters": {
                    const result = await listFilters(gmail);
                    const filters = result.filters;

                    if (filters.length === 0) {
                        return {
                            content: [
                                {
                                    type: "text",
                                    text: "No filters found.",
                                },
                            ],
                        };
                    }

                    const filtersText = filters.map((filter: any) => {
                        const criteriaEntries = Object.entries(filter.criteria || {})
                            .filter(([_, value]) => value !== undefined)
                            .map(([key, value]) => `${key}: ${value}`)
                            .join(', ');
                        
                        const actionEntries = Object.entries(filter.action || {})
                            .filter(([_, value]) => value !== undefined && (Array.isArray(value) ? value.length > 0 : true))
                            .map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join(', ') : value}`)
                            .join(', ');

                        return `ID: ${filter.id}\nCriteria: ${criteriaEntries}\nActions: ${actionEntries}\n`;
                    }).join('\n');

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Found ${result.count} filters:\n\n${filtersText}`,
                            },
                        ],
                    };
                }

                case "get_filter": {
                    const validatedArgs = GetFilterSchema.parse(args);
                    const result = await getFilter(gmail, validatedArgs.filterId);

                    const criteriaText = Object.entries(result.criteria || {})
                        .filter(([_, value]) => value !== undefined)
                        .map(([key, value]) => `${key}: ${value}`)
                        .join(', ');
                    
                    const actionText = Object.entries(result.action || {})
                        .filter(([_, value]) => value !== undefined && (Array.isArray(value) ? value.length > 0 : true))
                        .map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join(', ') : value}`)
                        .join(', ');

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Filter details:\nID: ${result.id}\nCriteria: ${criteriaText}\nActions: ${actionText}`,
                            },
                        ],
                    };
                }

                case "delete_filter": {
                    const validatedArgs = DeleteFilterSchema.parse(args);
                    const result = await deleteFilter(gmail, validatedArgs.filterId);

                    return {
                        content: [
                            {
                                type: "text",
                                text: result.message,
                            },
                        ],
                    };
                }

                case "create_filter_from_template": {
                    const validatedArgs = CreateFilterFromTemplateSchema.parse(args);
                    const template = validatedArgs.template;
                    const params = validatedArgs.parameters;

                    let filterConfig;
                    
                    switch (template) {
                        case 'fromSender':
                            if (!params.senderEmail) throw new Error("senderEmail is required for fromSender template");
                            filterConfig = filterTemplates.fromSender(params.senderEmail, params.labelIds, params.archive);
                            break;
                        case 'withSubject':
                            if (!params.subjectText) throw new Error("subjectText is required for withSubject template");
                            filterConfig = filterTemplates.withSubject(params.subjectText, params.labelIds, params.markAsRead);
                            break;
                        case 'withAttachments':
                            filterConfig = filterTemplates.withAttachments(params.labelIds);
                            break;
                        case 'largeEmails':
                            if (!params.sizeInBytes) throw new Error("sizeInBytes is required for largeEmails template");
                            filterConfig = filterTemplates.largeEmails(params.sizeInBytes, params.labelIds);
                            break;
                        case 'containingText':
                            if (!params.searchText) throw new Error("searchText is required for containingText template");
                            filterConfig = filterTemplates.containingText(params.searchText, params.labelIds, params.markImportant);
                            break;
                        case 'mailingList':
                            if (!params.listIdentifier) throw new Error("listIdentifier is required for mailingList template");
                            filterConfig = filterTemplates.mailingList(params.listIdentifier, params.labelIds, params.archive);
                            break;
                        default:
                            throw new Error(`Unknown template: ${template}`);
                    }

                    const result = await createFilter(gmail, filterConfig.criteria, filterConfig.action);

                    return {
                        content: [
                            {
                                type: "text",
                                text: `Filter created from template '${template}':\nID: ${result.id}\nTemplate used: ${template}`,
                            },
                        ],
                    };
                }
                case "download_attachment": {
                    const validatedArgs = DownloadAttachmentSchema.parse(args);

                    try {
                        // Allowlist guard: resolve the message's sender before fetching anything.
                        const senderMeta = await gmail.users.messages.get({
                            userId: 'me',
                            id: validatedArgs.messageId,
                            format: 'metadata',
                            metadataHeaders: ['From', 'Authentication-Results'],
                        });
                        const attFrom = senderMeta.data.payload?.headers
                            ?.find(h => h.name?.toLowerCase() === 'from')?.value || '';
                        const attBlock = readGuard(attFrom, 'This attachment', senderMeta.data.payload as GmailMessagePart);
                        if (attBlock) return attBlock;

                        // Get the attachment data from Gmail API
                        const attachmentResponse = await gmail.users.messages.attachments.get({
                            userId: 'me',
                            messageId: validatedArgs.messageId,
                            id: validatedArgs.attachmentId,
                        });

                        if (!attachmentResponse.data.data) {
                            throw new Error('No attachment data received');
                        }

                        // Decode the base64 data
                        const data = attachmentResponse.data.data;
                        const buffer = Buffer.from(data, 'base64url');

                        // Determine save path and filename
                        const savePath = validatedArgs.savePath || process.cwd();
                        let filename = validatedArgs.filename;

                        if (!filename) {
                            // Get original filename from message if not provided
                            const messageResponse = await gmail.users.messages.get({
                                userId: 'me',
                                id: validatedArgs.messageId,
                                format: 'full',
                            });

                            // Find the attachment part to get original filename
                            const findAttachment = (part: any): string | null => {
                                if (part.body && part.body.attachmentId === validatedArgs.attachmentId) {
                                    return part.filename || `attachment-${validatedArgs.attachmentId}`;
                                }
                                if (part.parts) {
                                    for (const subpart of part.parts) {
                                        const found = findAttachment(subpart);
                                        if (found) return found;
                                    }
                                }
                                return null;
                            };

                            filename = findAttachment(messageResponse.data.payload) || `attachment-${validatedArgs.attachmentId}`;
                        }

                        // Sanitize filename to prevent path traversal
                        filename = path.basename(filename);

                        // Ensure save directory exists
                        if (!fs.existsSync(savePath)) {
                            fs.mkdirSync(savePath, { recursive: true });
                        }

                        // Resolve and validate final path stays within savePath
                        const resolvedSavePath = path.resolve(savePath);
                        const fullPath = path.resolve(resolvedSavePath, filename);
                        if (!fullPath.startsWith(resolvedSavePath + path.sep) && fullPath !== resolvedSavePath) {
                            throw new Error('Invalid filename: path traversal detected');
                        }
                        fs.writeFileSync(fullPath, buffer);

                        return {
                            content: [
                                {
                                    type: "text",
                                    text: `Attachment downloaded successfully:\nFile: ${filename}\nSize: ${buffer.length} bytes\nSaved to: ${fullPath}`,
                                },
                            ],
                        };
                    } catch (error: any) {
                        return {
                            isError: true,
                            content: [
                                {
                                    type: "text",
                                    text: `Failed to download attachment: ${error.message}`,
                                },
                            ],
                        };
                    }
                }

                case "get_thread": {
                    const validatedArgs = GetThreadSchema.parse(args);
                    const threadResponse = await gmail.users.threads.get({
                        userId: 'me',
                        id: validatedArgs.threadId,
                        format: validatedArgs.format || 'full',
                    });

                    const threadMessages = threadResponse.data.messages || [];

                    // Process each message in the thread (already chronological from API)
                    const messagesOutput = threadMessages.map((msg) => {
                        const headers = msg.payload?.headers || [];
                        const subject = headers.find(h => h.name?.toLowerCase() === 'subject')?.value || '';
                        const from = headers.find(h => h.name?.toLowerCase() === 'from')?.value || '';
                        const to = headers.find(h => h.name?.toLowerCase() === 'to')?.value || '';
                        const cc = headers.find(h => h.name?.toLowerCase() === 'cc')?.value || '';
                        const bcc = headers.find(h => h.name?.toLowerCase() === 'bcc')?.value || '';
                        const date = headers.find(h => h.name?.toLowerCase() === 'date')?.value || '';

                        // Extract body content
                        let body = '';
                        if (validatedArgs.format !== 'minimal') {
                            const { text, html } = extractEmailContent(msg.payload as GmailMessagePart || {});
                            body = text || html || '';
                        }

                        // Extract attachment metadata
                        const attachments: EmailAttachment[] = [];
                        const processAttachmentParts = (part: GmailMessagePart) => {
                            if (part.body && part.body.attachmentId) {
                                const filename = part.filename || `attachment-${part.body.attachmentId}`;
                                attachments.push({
                                    id: part.body.attachmentId,
                                    filename: filename,
                                    mimeType: part.mimeType || 'application/octet-stream',
                                    size: part.body.size || 0,
                                });
                            }
                            if (part.parts) {
                                part.parts.forEach((subpart: GmailMessagePart) => processAttachmentParts(subpart));
                            }
                        };
                        if (msg.payload) {
                            processAttachmentParts(msg.payload as GmailMessagePart);
                        }

                        return {
                            messageId: msg.id || '',
                            threadId: msg.threadId || '',
                            from,
                            to,
                            cc,
                            bcc,
                            subject,
                            date,
                            body,
                            labelIds: msg.labelIds || [],
                            attachments: attachments.map(a => ({
                                filename: a.filename,
                                mimeType: a.mimeType,
                                size: a.size,
                            })),
                        };
                    });

                    // Allowlist guard: only surface messages from trusted senders.
                    // When GMAIL_REQUIRE_AUTH is on, also require DMARC pass (from the raw payloads).
                    const authedIds = new Set(threadMessages.filter(msg => msg.id && dmarcPassed(msg.payload as GmailMessagePart)).map(msg => msg.id!));
                    const visibleMessages = messagesOutput.filter(m => isAllowed(m.from, readAllowlist) && (!requireAuth || authedIds.has(m.messageId)));
                    const withheldCount = messagesOutput.length - visibleMessages.length;

                    return {
                        content: [
                            {
                                type: "text",
                                text: JSON.stringify({
                                    threadId: validatedArgs.threadId,
                                    messageCount: visibleMessages.length,
                                    withheldCount,
                                    messages: visibleMessages,
                                }, null, 2),
                            },
                        ],
                    };
                }

                case "list_inbox_threads": {
                    const validatedArgs = ListInboxThreadsSchema.parse(args);
                    const threadsResponse = await gmail.users.threads.list({
                        userId: 'me',
                        q: validatedArgs.query || 'in:inbox',
                        maxResults: validatedArgs.maxResults || 50,
                    });

                    const threads = threadsResponse.data.threads || [];

                    // Fetch metadata for each thread to get message count and latest message info
                    const threadDetails = await Promise.all(
                        threads.map(async (thread) => {
                            const detail = await gmail.users.threads.get({
                                userId: 'me',
                                id: thread.id!,
                                format: 'metadata',
                                metadataHeaders: ['Subject', 'From', 'Date', 'Authentication-Results'],
                            });

                            const messages = detail.data.messages || [];
                            const latestMessage = messages[messages.length - 1];
                            const latestHeaders = latestMessage?.payload?.headers || [];

                            return {
                                _authed: dmarcPassed(latestMessage?.payload as GmailMessagePart),
                                threadId: thread.id || '',
                                snippet: thread.snippet || '',
                                historyId: thread.historyId || '',
                                messageCount: messages.length,
                                latestMessage: {
                                    from: latestHeaders.find(h => h.name === 'From')?.value || '',
                                    subject: latestHeaders.find(h => h.name === 'Subject')?.value || '',
                                    date: latestHeaders.find(h => h.name === 'Date')?.value || '',
                                },
                            };
                        })
                    );

                    // Allowlist guard: only surface threads whose latest sender is trusted
                    // (and, when GMAIL_REQUIRE_AUTH is on, whose latest message passed DMARC).
                    const visibleThreads = threadDetails
                        .filter(t => isAllowed(t.latestMessage.from, readAllowlist) && (!requireAuth || t._authed))
                        .map(({ _authed, ...t }) => t);

                    return {
                        content: [
                            {
                                type: "text",
                                text: JSON.stringify({
                                    resultCount: visibleThreads.length,
                                    threads: visibleThreads,
                                }, null, 2),
                            },
                        ],
                    };
                }

                case "get_inbox_with_threads": {
                    const validatedArgs = GetInboxWithThreadsSchema.parse(args);
                    const threadsResponse = await gmail.users.threads.list({
                        userId: 'me',
                        q: validatedArgs.query || 'in:inbox',
                        maxResults: validatedArgs.maxResults || 50,
                    });

                    const threads = threadsResponse.data.threads || [];

                    if (!validatedArgs.expandThreads) {
                        // Return basic thread list without expansion (same as list_inbox_threads)
                        const threadSummaries = await Promise.all(
                            threads.map(async (thread) => {
                                const detail = await gmail.users.threads.get({
                                    userId: 'me',
                                    id: thread.id!,
                                    format: 'metadata',
                                    metadataHeaders: ['Subject', 'From', 'Date', 'Authentication-Results'],
                                });

                                const messages = detail.data.messages || [];
                                const latestMessage = messages[messages.length - 1];
                                const latestHeaders = latestMessage?.payload?.headers || [];

                                return {
                                    _authed: dmarcPassed(latestMessage?.payload as GmailMessagePart),
                                    threadId: thread.id || '',
                                    snippet: thread.snippet || '',
                                    historyId: thread.historyId || '',
                                    messageCount: messages.length,
                                    latestMessage: {
                                        from: latestHeaders.find(h => h.name === 'From')?.value || '',
                                        subject: latestHeaders.find(h => h.name === 'Subject')?.value || '',
                                        date: latestHeaders.find(h => h.name === 'Date')?.value || '',
                                    },
                                };
                            })
                        );

                        // Allowlist guard: only surface threads whose latest sender is trusted
                        // (and, when GMAIL_REQUIRE_AUTH is on, whose latest message passed DMARC).
                        const visibleSummaries = threadSummaries
                            .filter(t => isAllowed(t.latestMessage.from, readAllowlist) && (!requireAuth || t._authed))
                            .map(({ _authed, ...t }) => t);

                        return {
                            content: [
                                {
                                    type: "text",
                                    text: JSON.stringify({
                                        resultCount: visibleSummaries.length,
                                        threads: visibleSummaries,
                                    }, null, 2),
                                },
                            ],
                        };
                    }

                    // Expand each thread with full message content (parallel fetch)
                    const expandedThreads = await Promise.all(
                        threads.map(async (thread) => {
                            const threadDetail = await gmail.users.threads.get({
                                userId: 'me',
                                id: thread.id!,
                                format: 'full',
                            });

                            const threadMessages = threadDetail.data.messages || [];

                            const messages = threadMessages.map((msg) => {
                                const headers = msg.payload?.headers || [];
                                const subject = headers.find(h => h.name?.toLowerCase() === 'subject')?.value || '';
                                const from = headers.find(h => h.name?.toLowerCase() === 'from')?.value || '';
                                const to = headers.find(h => h.name?.toLowerCase() === 'to')?.value || '';
                                const cc = headers.find(h => h.name?.toLowerCase() === 'cc')?.value || '';
                                const bcc = headers.find(h => h.name?.toLowerCase() === 'bcc')?.value || '';
                                const date = headers.find(h => h.name?.toLowerCase() === 'date')?.value || '';

                                const { text, html } = extractEmailContent(msg.payload as GmailMessagePart || {});
                                const body = text || html || '';

                                // Extract attachment metadata
                                const attachments: EmailAttachment[] = [];
                                const processAttachmentParts = (part: GmailMessagePart) => {
                                    if (part.body && part.body.attachmentId) {
                                        const filename = part.filename || `attachment-${part.body.attachmentId}`;
                                        attachments.push({
                                            id: part.body.attachmentId,
                                            filename: filename,
                                            mimeType: part.mimeType || 'application/octet-stream',
                                            size: part.body.size || 0,
                                        });
                                    }
                                    if (part.parts) {
                                        part.parts.forEach((subpart: GmailMessagePart) => processAttachmentParts(subpart));
                                    }
                                };
                                if (msg.payload) {
                                    processAttachmentParts(msg.payload as GmailMessagePart);
                                }

                                return {
                                    messageId: msg.id || '',
                                    threadId: msg.threadId || '',
                                    from,
                                    to,
                                    cc,
                                    bcc,
                                    subject,
                                    date,
                                    body,
                                    labelIds: msg.labelIds || [],
                                    attachments: attachments.map(a => ({
                                        filename: a.filename,
                                        mimeType: a.mimeType,
                                        size: a.size,
                                    })),
                                };
                            });

                            // Allowlist guard: keep only messages from trusted senders.
                            const authedIds = new Set(threadMessages.filter(msg => msg.id && dmarcPassed(msg.payload as GmailMessagePart)).map(msg => msg.id!));
                            const visible = messages.filter(m => isAllowed(m.from, readAllowlist) && (!requireAuth || authedIds.has(m.messageId)));

                            return {
                                threadId: thread.id || '',
                                messageCount: visible.length,
                                withheldCount: messages.length - visible.length,
                                messages: visible,
                            };
                        })
                    );

                    // Drop threads that have no trusted messages left.
                    const visibleExpanded = expandedThreads.filter(t => t.messageCount > 0);

                    return {
                        content: [
                            {
                                type: "text",
                                text: JSON.stringify({
                                    resultCount: visibleExpanded.length,
                                    threads: visibleExpanded,
                                }, null, 2),
                            },
                        ],
                    };
                }

                case "reply_all": {
                    const validatedArgs = ReplyAllSchema.parse(args);

                    // Fetch the original email to get headers
                    const originalEmail = await gmail.users.messages.get({
                        userId: 'me',
                        id: validatedArgs.messageId,
                        format: 'full',
                    });

                    const headers = originalEmail.data.payload?.headers || [];
                    const threadId = originalEmail.data.threadId || '';

                    // Extract relevant headers
                    const originalFrom = headers.find(h => h.name?.toLowerCase() === 'from')?.value || '';
                    const originalTo = headers.find(h => h.name?.toLowerCase() === 'to')?.value || '';
                    const originalCc = headers.find(h => h.name?.toLowerCase() === 'cc')?.value || '';
                    const originalSubject = headers.find(h => h.name?.toLowerCase() === 'subject')?.value || '';
                    const originalMessageId = headers.find(h => h.name?.toLowerCase() === 'message-id')?.value || '';
                    const originalReferences = headers.find(h => h.name?.toLowerCase() === 'references')?.value || '';

                    // Get authenticated user's email to exclude from recipients
                    const profile = await gmail.users.getProfile({ userId: 'me' });
                    const myEmail = profile.data.emailAddress?.toLowerCase() || '';

                    // Build recipient list using helper functions
                    const { to: replyTo, cc: replyCc } = buildReplyAllRecipients(
                        originalFrom,
                        originalTo,
                        originalCc,
                        myEmail
                    );

                    if (replyTo.length === 0) {
                        throw new Error('Could not determine recipient for reply');
                    }

                    // Build subject with "Re:" prefix if not already present
                    const replySubject = addRePrefix(originalSubject);

                    // Build References header (original References + original Message-ID)
                    const references = buildReferencesHeader(originalReferences, originalMessageId);

                    // Prepare the email arguments for handleEmailAction
                    const emailArgs = {
                        to: replyTo,
                        cc: replyCc.length > 0 ? replyCc : undefined,
                        subject: replySubject,
                        body: validatedArgs.body,
                        htmlBody: validatedArgs.htmlBody,
                        mimeType: validatedArgs.mimeType,
                        threadId: threadId,
                        inReplyTo: originalMessageId,
                        attachments: validatedArgs.attachments,
                    };

                    // Use the existing handleEmailAction to send the reply
                    const result = await handleEmailAction("send", emailArgs);

                    // Enhance the response with reply-all specific info
                    return {
                        content: [
                            {
                                type: "text",
                                text: `Reply-all sent successfully!\nTo: ${replyTo.join(', ')}${replyCc.length > 0 ? `\nCC: ${replyCc.join(', ')}` : ''}\nSubject: ${replySubject}\nThread ID: ${threadId}`,
                            },
                        ],
                    };
                }

                default:
                    throw new Error(`Unknown tool: ${name}`);
            }
        } catch (error: any) {
            // Tool execution errors are reported in the result with isError: true,
            // not as JSON-RPC protocol errors — the spec wants them handed to the
            // model so it can self-correct and retry.
            return {
                isError: true,
                content: [
                    {
                        type: "text",
                        text: `Error: ${error.message}`,
                    },
                ],
            };
        }
    };

    // One instance per connection, built by serveStdio. The factory must be cheap
    // and side-effect-free: serveStdio may call it twice on a connection that
    // probes for the 2026-07-28 era and then falls back to the 2025 handshake.
    // All the expensive setup (OAuth, allowlist, profile lookup) already ran above.
    const buildServer = () => {
        const server = new Server(
            {
                name: "gmail",
                version: SERVER_VERSION,
            },
            {
                capabilities: {
                    tools: {},
                },
            },
        );
        server.setRequestHandler('tools/list', listToolsHandler);
        server.setRequestHandler('tools/call', callToolHandler);
        return server;
    };

    // serveStdio owns the transport and pins the connection's protocol era:
    // 2026-07-28 for clients that open with a modern per-request _meta envelope,
    // and the 2025-era initialize handshake for everyone else (legacy: 'serve').
    const handle = serveStdio(buildServer, {
        onerror: (error) => console.error('Server error:', error),
    });

    // Registering a handler replaces the default signal disposition, so this code
    // is now solely responsible for terminating: guard re-entry (a second Ctrl-C
    // must not restart the close) and keep an unref'd timer as the backstop for a
    // close() that never settles, so the process still dies on SIGINT/SIGTERM.
    let closing = false;
    const shutdown = () => {
        if (closing) return;
        closing = true;
        setTimeout(() => process.exit(0), 5000).unref();
        void handle.close().finally(() => process.exit(0));
    };
    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
}

main().catch((error) => {
    console.error('Server error:', error);
    process.exit(1);
});
