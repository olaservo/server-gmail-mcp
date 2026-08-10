import path from 'path';

/**
 * Confinement root for the tools that write mailbox content to disk
 * (`download_email`, `download_attachment`).
 *
 * Those tools take a model-supplied `savePath`. Without a root, a prompt
 * injection inside an allowlisted sender's mail can steer bytes anywhere the
 * server process can write. GMAIL_DOWNLOAD_DIR is therefore both the opt-in
 * that exposes the download tools in read-only mode and the boundary they are
 * held to.
 */

/** Resolve GMAIL_DOWNLOAD_DIR to an absolute path, or null when unset/blank. */
export function loadDownloadRoot(env: string | undefined): string | null {
    const value = (env || '').trim();
    return value ? path.resolve(value) : null;
}

/**
 * Resolve a requested save directory against the configured root.
 *
 * With a root set, relative paths are interpreted inside it and anything that
 * escapes it throws. With no root (write tools enabled, no GMAIL_DOWNLOAD_DIR),
 * the requested path is used as-is — the historical behaviour.
 */
export function resolveDownloadPath(
    requested: string | undefined,
    root: string | null,
    fallback: string,
): string {
    if (root === null) {
        return path.resolve(requested || fallback);
    }
    const target = path.resolve(root, requested || '.');
    const rel = path.relative(root, target);
    // path.relative is case-insensitive on win32, so this holds on both platforms.
    if (rel.startsWith('..') || path.isAbsolute(rel)) {
        throw new Error(
            `Refusing to write outside GMAIL_DOWNLOAD_DIR (${root}): requested ${target}`,
        );
    }
    return target;
}
