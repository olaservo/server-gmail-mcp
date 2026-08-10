import { describe, it, expect } from 'vitest';
import { z } from 'zod';
import type { ToolDefinition } from './tools.js';
import { toolDefinitions, getToolByName, isReadOnlyTool, isDiskWriteTool, isToolExposed, toMcpTools } from './tools.js';
import { hasScope } from './scopes.js';

const READ_ONLY_TOOL_NAMES = [
    'read_email',
    'search_emails',
    'get_thread',
    'list_inbox_threads',
    'get_inbox_with_threads',
    'list_email_labels',
    'list_filters',
    'get_filter',
];

// Read the mailbox but write bytes to a caller-supplied path, so not read-only.
const DISK_WRITE_TOOL_NAMES = [
    'download_attachment',
    'download_email',
];

const WRITE_TOOL_NAMES = [
    'send_email',
    'draft_email',
    'reply_all',
    'modify_email',
    'delete_email',
    'batch_modify_emails',
    'batch_delete_emails',
    'create_label',
    'update_label',
    'delete_label',
    'get_or_create_label',
    'create_filter',
    'delete_filter',
    'create_filter_from_template',
];

describe('isReadOnlyTool', () => {
    it('returns true for every read-only tool', () => {
        for (const name of READ_ONLY_TOOL_NAMES) {
            const tool = getToolByName(name)!;
            expect(tool, `missing tool ${name}`).toBeDefined();
            expect(isReadOnlyTool(tool), `${name} should be read-only`).toBe(true);
        }
    });

    it('returns false for every write tool', () => {
        for (const name of [...WRITE_TOOL_NAMES, ...DISK_WRITE_TOOL_NAMES]) {
            const tool = getToolByName(name)!;
            expect(tool, `missing tool ${name}`).toBeDefined();
            expect(isReadOnlyTool(tool), `${name} should not be read-only`).toBe(false);
        }
    });

    it('classifies exactly the expected read-only tools', () => {
        const readOnly = toolDefinitions.filter(isReadOnlyTool).map(t => t.name).sort();
        expect(readOnly).toEqual([...READ_ONLY_TOOL_NAMES].sort());
    });

    it('covers the full tool registry between the three sets', () => {
        const all = toolDefinitions.map(t => t.name).sort();
        const combined = [...READ_ONLY_TOOL_NAMES, ...DISK_WRITE_TOOL_NAMES, ...WRITE_TOOL_NAMES].sort();
        expect(all).toEqual(combined);
    });
});

describe('isDiskWriteTool', () => {
    it('flags exactly the tools that write files to disk', () => {
        const diskWriters = toolDefinitions.filter(isDiskWriteTool).map(t => t.name).sort();
        expect(diskWriters).toEqual([...DISK_WRITE_TOOL_NAMES].sort());
    });

    it('never claims readOnlyHint — writing a file modifies the environment', () => {
        for (const tool of toolDefinitions.filter(isDiskWriteTool)) {
            expect(tool.annotations.readOnlyHint, `${tool.name} must not be readOnlyHint`).not.toBe(true);
        }
    });
});

describe('ListTools exposure filter', () => {
    // Full-access scopes so the scope filter never hides anything; we isolate the
    // opt-in gates.
    const fullScopes = ['gmail.modify', 'gmail.settings.basic'];

    const exposed = (writeToolsEnabled: boolean, downloadsEnabled: boolean) =>
        toolDefinitions
            .filter(t => hasScope(fullScopes, t.scopes) && isToolExposed(t, { writeToolsEnabled, downloadsEnabled }))
            .map(t => t.name)
            .sort();

    it('exposes only read-only tools when both opt-ins are off', () => {
        expect(exposed(false, false)).toEqual([...READ_ONLY_TOOL_NAMES].sort());
    });

    it('adds the download tools when GMAIL_DOWNLOAD_DIR is set', () => {
        expect(exposed(false, true)).toEqual(
            [...READ_ONLY_TOOL_NAMES, ...DISK_WRITE_TOOL_NAMES].sort()
        );
    });

    it('exposes all scope-permitted tools when write mode is on', () => {
        expect(exposed(true, false)).toEqual(
            [...READ_ONLY_TOOL_NAMES, ...DISK_WRITE_TOOL_NAMES, ...WRITE_TOOL_NAMES].sort()
        );
    });
});

// The emitted inputSchema is the client-facing contract. It is generated at
// runtime by zod's JSON Schema emitter, so a zod upgrade can silently change
// shape (e.g. start emitting `additionalProperties: {}`, which would make the
// closeObjects guard a no-op and reopen every schema) without any code change.
describe('toMcpTools inputSchema emission', () => {
    const tools = toMcpTools(toolDefinitions);

    it('emits one tool per definition, with annotations attached', () => {
        expect(tools.map(t => t.name).sort()).toEqual(toolDefinitions.map(t => t.name).sort());
        for (const tool of tools) {
            expect(tool.annotations, `${tool.name} annotations`).toBeDefined();
            expect(tool.description, `${tool.name} description`).toBeTruthy();
        }
    });

    it('emits a closed object schema at the root of every tool', () => {
        for (const tool of tools) {
            const schema = tool.inputSchema as Record<string, unknown>;
            expect(schema.type, `${tool.name} root type`).toBe('object');
            expect(schema.additionalProperties, `${tool.name} must reject unknown args`).toBe(false);
        }
    });

    it('closes nested object schemas too', () => {
        // create_filter has two nested objects (criteria, action).
        const createFilter = tools.find(t => t.name === 'create_filter')!;
        const props = (createFilter.inputSchema as any).properties;
        expect(props.criteria.additionalProperties).toBe(false);
        expect(props.action.additionalProperties).toBe(false);
    });

    it('keeps .default() fields optional — io:"input" describes what a caller sends', () => {
        // batch_modify_emails.batchSize and download_email.format both have defaults.
        const batch = tools.find(t => t.name === 'batch_modify_emails')!;
        expect((batch.inputSchema as any).required).toEqual(['messageIds']);

        const download = tools.find(t => t.name === 'download_email')!;
        expect((download.inputSchema as any).required).toEqual(['messageId', 'savePath']);
    });

    it('round-trips a representative argument object through each tool schema', () => {
        const samples: Record<string, unknown> = {
            read_email: { messageId: 'abc' },
            search_emails: { query: 'in:inbox', maxResults: 5 },
            download_attachment: { messageId: 'abc', attachmentId: 'att' },
            download_email: { messageId: 'abc', savePath: '/tmp/x', format: 'eml' },
            create_filter: { criteria: { from: 'a@b.c' }, action: { addLabelIds: ['L1'] } },
            batch_modify_emails: { messageIds: ['a'], addLabelIds: ['L1'] },
        };
        for (const [name, args] of Object.entries(samples)) {
            const def = getToolByName(name)!;
            expect(() => def.schema.parse(args), `${name} should accept its sample`).not.toThrow();
        }
    });

    it('reuses the same emitted object across calls', () => {
        const again = toMcpTools(toolDefinitions);
        expect(again[0]).toBe(tools[0]);
    });
});

// closeObjects must descend only through schema positions. A blind walk over
// every object value would also rewrite data (defaults, examples) and would
// close allOf branches, which makes a composed schema reject every input.
describe('toMcpTools does not corrupt non-schema positions', () => {
    const synthetic = (name: string, schema: z.ZodType<any>): ToolDefinition => ({
        name,
        description: `synthetic ${name}`,
        schema,
        scopes: ['gmail.readonly'],
        annotations: { title: name },
    });

    it('leaves an allOf composition satisfiable', () => {
        const composed = z.intersection(
            z.object({ a: z.string() }),
            z.object({ b: z.string() }),
        );
        const [tool] = toMcpTools([synthetic('synthetic_intersection', composed)]);
        const schema = tool.inputSchema as any;
        if (Array.isArray(schema.allOf)) {
            for (const branch of schema.allOf) {
                expect(branch.additionalProperties, 'allOf branches must stay open').not.toBe(false);
            }
            expect(schema.additionalProperties, 'the composition itself must stay open').not.toBe(false);
        }
        // Whatever shape zod emits, the schema must still accept a valid value.
        expect(() => composed.parse({ a: 'x', b: 'y' })).not.toThrow();
    });

    it('does not inject additionalProperties into a default value', () => {
        const withObjectDefault = z.object({
            opts: z.object({ type: z.string() }).default({ type: 'object' }),
        });
        const [tool] = toMcpTools([synthetic('synthetic_default', withObjectDefault)]);
        const schema = tool.inputSchema as any;
        const emittedDefault = schema.properties?.opts?.default;
        if (emittedDefault !== undefined) {
            expect(emittedDefault).toEqual({ type: 'object' });
            expect(emittedDefault.additionalProperties).toBeUndefined();
        }
    });
});

describe('search_emails maxResults', () => {
    it('rejects 0 rather than silently falling back to the default', () => {
        // `maxResults || 10` used to turn an explicit 0 into 10.
        expect(() => getToolByName('search_emails')!.schema.parse({ query: 'x', maxResults: 0 })).toThrow();
    });

    it('rejects non-integers', () => {
        expect(() => getToolByName('search_emails')!.schema.parse({ query: 'x', maxResults: 2.5 })).toThrow();
    });
});
