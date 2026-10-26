// Document helpers for the admin page. The page edits a document as one
// text field per leaf, each named by its claims path: the object keys and
// array indices that lead to it. Each entry keeps the JSON type of its
// leaf, which unflattenEntries gives the edited text back.

/** @typedef {(string|number)[]} LeafPath */
/** @typedef {"string"|"number"|"boolean"|"null"|"object"|"array"} LeafType */
/** @typedef {{ path: LeafPath; value: string; type: LeafType }} DocumentEntry */

/**
 * Flatten a document into one entry per leaf, in document order. A leaf is
 * a string, a number, a boolean, null, or an empty object or array below
 * the top level, whose text is its JSON.
 * @param {unknown} value
 * @param {LeafPath} [path]
 * @returns {DocumentEntry[]}
 */
export function flattenDocument(value, path = []) {
    const members = Array.isArray(value)
        ? value.map((element, i) => /** @type {[string|number, unknown]} */ ([i, element]))
        : value !== null && typeof value === "object" ? Object.entries(value) : null;
    if (members === null) {
        return [leafEntry(value, path)];
    }
    if (members.length === 0 && path.length > 0) {
        return [{ path, value: JSON.stringify(value), type: Array.isArray(value) ? "array" : "object" }];
    }
    return members.flatMap(([key, member]) => flattenDocument(member, [...path, key]));
}

/**
 * The entry of a scalar leaf.
 * @param {unknown} value
 * @param {LeafPath} path
 * @returns {DocumentEntry}
 */
function leafEntry(value, path) {
    switch (typeof value) {
        case "number":
            return { path, value: String(value), type: "number" };
        case "boolean":
            return { path, value: String(value), type: "boolean" };
        case "string":
            return { path, value, type: "string" };
    }
    if (value === null) {
        return { path, value: "", type: "null" };
    }
    throw new Error(`${JSON.stringify(path)}: a document holds no ${typeof value}`);
}

/**
 * Rebuild a document from its entries: an object where a path continues
 * with a key, an array where it continues with an index. Each leaf takes
 * the type of its entry; a text that is no value of that type throws.
 * @param {DocumentEntry[]} entries
 * @returns {Record<string, unknown>}
 */
export function unflattenEntries(entries) {
    /** @type {Record<string, unknown>} */
    const document = {};
    for (const entry of entries) {
        const { path } = entry;
        /** @type {any} */
        let container = document;
        for (let i = 0; i < path.length - 1; i++) {
            container = childContainer(container, path[i], typeof path[i + 1] === "number");
        }
        container[path[path.length - 1]] = leafValue(entry);
    }
    return document;
}

/**
 * The value of an entry's text, in the entry's type. The text of a null
 * leaf that was edited is a string.
 * @param {DocumentEntry} entry
 * @returns {unknown}
 */
function leafValue({ path, value, type }) {
    const refuse = () => new Error(`${JSON.stringify(path)}: ${JSON.stringify(value)} is no ${type}`);
    switch (type) {
        case "string":
            return value;
        case "null":
            return value === "" ? null : value;
        case "number": {
            const number = Number(value);
            if (value.trim() === "" || !Number.isFinite(number)) throw refuse();
            return number;
        }
        case "boolean":
            if (value !== "true" && value !== "false") throw refuse();
            return value === "true";
        case "object":
        case "array": {
            let parsed;
            try {
                parsed = JSON.parse(value);
            } catch {
                throw refuse();
            }
            if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed) !== (type === "array")) throw refuse();
            return parsed;
        }
    }
    throw refuse();
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
