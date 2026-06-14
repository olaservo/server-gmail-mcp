import { describe, it, expect } from 'vitest';
import { toolDefinitions, getToolByName, isReadOnlyTool } from './tools.js';
import { hasScope } from './scopes.js';

const READ_ONLY_TOOL_NAMES = [
    'read_email',
    'search_emails',
    'download_attachment',
    'download_email',
    'get_thread',
    'list_inbox_threads',
    'get_inbox_with_threads',
    'list_email_labels',
    'list_filters',
    'get_filter',
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
        for (const name of WRITE_TOOL_NAMES) {
            const tool = getToolByName(name)!;
            expect(tool, `missing tool ${name}`).toBeDefined();
            expect(isReadOnlyTool(tool), `${name} should be a write tool`).toBe(false);
        }
    });

    it('classifies exactly the expected read-only tools', () => {
        const readOnly = toolDefinitions.filter(isReadOnlyTool).map(t => t.name).sort();
        expect(readOnly).toEqual([...READ_ONLY_TOOL_NAMES].sort());
    });

    it('covers the full tool registry between the two sets', () => {
        const all = toolDefinitions.map(t => t.name).sort();
        const combined = [...READ_ONLY_TOOL_NAMES, ...WRITE_TOOL_NAMES].sort();
        expect(all).toEqual(combined);
    });
});

describe('ListTools exposure filter (writeToolsEnabled || isReadOnlyTool)', () => {
    // Full-access scopes so the scope filter never hides anything; we isolate the
    // write-mode gate behavior.
    const fullScopes = ['gmail.modify', 'gmail.settings.basic'];

    const exposed = (writeToolsEnabled: boolean) =>
        toolDefinitions
            .filter(t => hasScope(fullScopes, t.scopes) && (writeToolsEnabled || isReadOnlyTool(t)))
            .map(t => t.name)
            .sort();

    it('exposes only read-only tools when write mode is off', () => {
        expect(exposed(false)).toEqual([...READ_ONLY_TOOL_NAMES].sort());
    });

    it('exposes all scope-permitted tools when write mode is on', () => {
        expect(exposed(true)).toEqual(
            [...READ_ONLY_TOOL_NAMES, ...WRITE_TOOL_NAMES].sort()
        );
    });
});
