// Unit tests for the admin page's document helpers. Runs under Node's
// built-in test runner (`node --test`, see the Makefile's test-js target).

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { flattenDocument, unflattenEntries } from "../admin-helpers.js";

describe("flattenDocument and unflattenEntries", () => {
    it("round-trip a document whose leaves are strings, through objects and arrays", () => {
        const document = {
            given_name: "Arthur",
            address: { locality: "Milliways", lines: ["42 Market Street", "Floor 2"] },
            elm: { credentialSubject: { hasClaim: ["", { awardedBy: { legalName: { en: "University of Betelgeuse" } } }] } },
            "1": { "0": "a key that reads as a number" },
        };
        assert.deepEqual(unflattenEntries(flattenDocument(document)), document);
    });
});
