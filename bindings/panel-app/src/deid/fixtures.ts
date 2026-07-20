// Test fixtures. SYNTHETIC, and deliberately so (I8).
//
// The TCKN below is NOT checksum-valid and the name is not a real patient's.
// This file is committed; a checksum-valid TCKN in the repository is blocked by
// the pre-commit hook for the same reason it would be blocked in a fixture.
//
// THE SHAPE OF THIS FIXTURE IS THE POINT. It contains a TCKN that IS masked and
// a PATIENT_NAME that is NOT, because that is the exact configuration this
// build ships in and the exact one the blackout animation could lie about.

import type { DetectedSpan } from "./types";

export const DOC = "Hasta Ayse Yilmaz, TCKN 12345678901, tel 0532 111 22 33.";

/**
 * A masked TCKN.
 *
 * Byte offsets: `DOC` is ASCII here so bytes and string indices coincide, which
 * they would not in a real Turkish note. `compose.test.ts` carries a separate
 * multi-byte case for that.
 */
export const TCKN_SPAN: DetectedSpan = {
  start: 24,
  end: 35,
  label: "TCKN",
  layer: "Rules",
  decision: "mask",
  confidence: 1,
  checksumValidated: true,
  replacement: "98765432109",
};

/**
 * A PATIENT_NAME the pipeline detected and DID NOT mask.
 *
 * `decision: "keep"` is what L4 emits for a span it declined, and in this build
 * it is what every name span would be, because L2 has no model to raise the
 * confidence that would make one maskable. This is the span that must never get
 * a bar.
 */
export const NAME_SPAN: DetectedSpan = {
  start: 6,
  end: 17,
  label: "PATIENT_NAME",
  layer: "Ner",
  decision: "keep",
  confidence: 0.4,
  checksumValidated: false,
  replacement: "Zeynep Kaya",
};

/** A phone number below whatever threshold the test sets. */
export const PHONE_SPAN: DetectedSpan = {
  start: 41,
  end: 55,
  label: "PHONE",
  layer: "Rules",
  decision: "mask",
  confidence: 0.6,
  checksumValidated: false,
  replacement: "0500 000 00 00",
};

export const SPANS: DetectedSpan[] = [NAME_SPAN, TCKN_SPAN, PHONE_SPAN];

export const OPEN_POLICY = {
  disabled: new Set<string>(),
  methods: new Map<string, string>(),
  threshold: 0,
  shiftDays: 0,
};
