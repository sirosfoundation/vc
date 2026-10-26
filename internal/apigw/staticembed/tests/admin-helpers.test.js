// Unit tests for the admin page's document helpers. Runs under Node's
// built-in test runner (`node --test`, see the Makefile's test-js target).

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { flattenDocument, unflattenEntries } from "../admin-helpers.js";

describe("flattenDocument and unflattenEntries", () => {
    it("round-trip a document through objects and arrays, each leaf in its JSON type", () => {
        const document = {
            given_name: "Arthur",
            address: { locality: "Milliways", lines: ["42 Market Street", "Floor 2"] },
            elm: { credentialSubject: { hasClaim: ["", { awardedBy: { legalName: { en: "University of Betelgeuse" } } }] } },
            "1": { "0": "a key that reads as a number" },
            age: 42,
            ratio: -0.5,
            over_18: true,
            over_65: false,
            middle_name: null,
            "42": "a string that reads as a number",
            extras: {},
            nationalities: [],
            nested: [{}, [], [0, "0", false]],
        };
        assert.deepEqual(unflattenEntries(flattenDocument(document)), document);
    });

    it("refuse a text that is no value of its leaf's type", () => {
        for (const [type, value] of [["number", "forty-two"], ["number", ""], ["boolean", "yes"], ["object", "[]"], ["array", "{"]]) {
            assert.throws(() => unflattenEntries([{ path: ["a"], value, type: /** @type {any} */ (type) }]));
        }
    });
});
