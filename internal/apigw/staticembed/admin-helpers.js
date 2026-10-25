// Document helpers for the admin page. The page edits a document as one
// text field per leaf, each named by its claims path: the object keys and
// array indices that lead to it.

/** @typedef {(string|number)[]} LeafPath */
/** @typedef {{ path: LeafPath; value: string }} DocumentEntry */

/**
 * Flatten a document into one entry per leaf, in document order. An empty
 * object or array has no leaf, and so no entry.
 * @param {unknown} value
 * @param {LeafPath} [path]
 * @returns {DocumentEntry[]}
 */
export function flattenDocument(value, path = []) {
    if (Array.isArray(value)) {
        return value.flatMap((element, i) => flattenDocument(element, [...path, i]));
    }
    if (value !== null && typeof value === "object") {
        return Object.entries(value).flatMap(([key, member]) => flattenDocument(member, [...path, key]));
    }
    return [{ path, value: value == null ? "" : String(value) }];
}

/**
 * Rebuild a document from its entries: an object where a path continues
 * with a key, an array where it continues with an index.
 * @param {DocumentEntry[]} entries
 * @returns {Record<string, unknown>}
 */
export function unflattenEntries(entries) {
    /** @type {Record<string, unknown>} */
    const document = {};
    for (const { path, value } of entries) {
        /** @type {any} */
        let container = document;
        for (let i = 0; i < path.length - 1; i++) {
            container = childContainer(container, path[i], typeof path[i + 1] === "number");
        }
        container[path[path.length - 1]] = value;
    }
    return document;
}

/**
 * Return the container at key in container, replacing a value of the other
 * kind.
 * @param {any} container
 * @param {string|number} key
 * @param {boolean} array
 * @returns {any}
 */
function childContainer(container, key, array) {
    const child = container[key];
    if (child === null || typeof child !== "object" || Array.isArray(child) !== array) {
        container[key] = array ? [] : {};
    }
    return container[key];
}

/**
 * The label of a path component: a key, or "[i]" for an array index.
 * @param {string|number} component
 * @returns {string}
 */
function componentLabel(component) {
    return typeof component === "number" ? `[${component}]` : component;
}

/**
 * Build the tree view rows of the entries: a group row for each object or
 * array, the first time an entry passes through it, and a field row for each
 * entry.
 * @param {DocumentEntry[]} entries
 * @returns {{ type: "group"|"field"; label: string; depth: number; idx: number }[]}
 */
export function buildTreeView(entries) {
    /** @type {{ type: "group"|"field"; label: string; depth: number; idx: number }[]} */
    const rows = [];
    const seenGroups = new Set();
    entries.forEach(({ path }, idx) => {
        for (let depth = 0; depth < path.length - 1; depth++) {
            const group = JSON.stringify(path.slice(0, depth + 1));
            if (!seenGroups.has(group)) {
                seenGroups.add(group);
                rows.push({ type: "group", label: componentLabel(path[depth]), depth, idx: -1 });
            }
        }
        rows.push({ type: "field", label: componentLabel(path[path.length - 1]), depth: path.length - 1, idx });
    });
    return rows;
}
