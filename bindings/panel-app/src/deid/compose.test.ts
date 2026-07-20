import { describe, expect, it } from "vitest";
import { compose, maskedCount, spanCount } from "./compose";
import { apply, family, sigil } from "./policy";
import { DOC, OPEN_POLICY, SPANS, TCKN_SPAN } from "./fixtures";
import type { DetectedSpan } from "./types";

describe("compose", () => {
  it("slices on UTF-8 byte offsets, not JavaScript string indices", () => {
    // THE FAILURE THIS TEST EXISTS FOR: `doc.slice(start, end)` drifts one
    // position per non-ASCII character and eventually splits a letter in half.
    // "Şükrü" is 5 characters and 8 bytes; a string-index slice of 6..17 would
    // land three characters late and cut into a multi-byte sequence.
    const doc = "Hasta Şükrü Öz, TCKN 12345678901.";
    const bytes = new TextEncoder().encode(doc);
    const start = bytes.indexOf(49); // the first '1' of the TCKN
    const span: DetectedSpan = { ...TCKN_SPAN, start, end: start + 11 };

    const { segments, output } = compose(doc, [span], OPEN_POLICY);
    const masked = segments.find((s) => s.kind === "span");
    expect(masked?.kind === "span" && masked.original).toBe("12345678901");
    expect(output).toBe("Hasta Şükrü Öz, TCKN 98765432109.");
    // And the Turkish characters survived the round trip intact.
    expect(output).toContain("Şükrü");
  });

  it("counts detected and masked separately", () => {
    const { segments } = compose(DOC, SPANS, OPEN_POLICY);
    expect(spanCount(segments)).toBe(3);
    // The name is detected and NOT masked. Two numbers, not one, precisely so
    // that this gap is visible rather than averaged away.
    expect(maskedCount(segments)).toBe(2);
  });

  it("leaves a kept span's text in the output unchanged", () => {
    const { output } = compose(DOC, SPANS, OPEN_POLICY);
    expect(output).toContain("Ayse Yilmaz");
  });

  it("honours L4's keep ahead of the user's controls", () => {
    // The order of authority: a span L4 declined stays declined even when every
    // panel control would have masked it.
    const { segments } = compose(DOC, SPANS, { ...OPEN_POLICY, threshold: 0 });
    const name = segments.find(
      (s) => s.kind === "span" && s.span.label === "PATIENT_NAME",
    );
    expect(name?.kind === "span" && name.passthrough).toBe("L4 kept it");
  });

  it("tracks output offsets through a replacement that changes length", () => {
    const { segments, output } = compose(DOC, SPANS, OPEN_POLICY);
    for (const segment of segments) {
      if (segment.kind !== "span") continue;
      const slice = new TextDecoder().decode(
        new TextEncoder()
          .encode(output)
          .subarray(segment.outputStart, segment.outputEnd),
      );
      expect(slice).toBe(segment.replacement);
    }
  });
});

describe("policy, pinned to the vanilla panel's answers", () => {
  it("groups labels into the same families the vanilla panel does", () => {
    expect(family("TCKN")).toBe("id");
    expect(family("IBAN")).toBe("id");
    expect(family("PHONE")).toBe("contact");
    expect(family("DATE_BIRTH")).toBe("date");
    expect(family("ADDRESS_STREET")).toBe("place");
    expect(family("PATIENT_NAME")).toBe("name");
    // Including the branch that is arguably wrong: `_NAME` is tested first, so
    // FACILITY_NAME lands in "name". See the comment in policy.ts.
    expect(family("FACILITY_NAME")).toBe("name");
  });

  it("carries the family in a sigil as well as a hue", () => {
    expect(sigil("id")).toBe("ID");
    expect(sigil("name")).toBe("NM");
    // Every family has one. A family that fell through to a blank would leave
    // a colour-blind reader with nothing.
    for (const f of ["id", "contact", "date", "place", "name", "other"] as const) {
      expect(sigil(f)).toHaveLength(2);
    }
  });

  it("does not republish the identifier's length when redacting", () => {
    const short = apply("redact", TCKN_SPAN, "1234", 0);
    const long = apply("redact", TCKN_SPAN, "123456789012345", 0);
    expect(short.text).toBe(long.text);
  });

  it("says so when date-shift could not parse the span", () => {
    const result = apply("date-shift", TCKN_SPAN, "not a date", 30);
    expect(result.text).toBe("[TCKN]");
    expect(result.note).toBe("not a parseable date, masked");
  });

  it("shifts a Turkish DD.MM.YYYY date across a month boundary", () => {
    expect(apply("date-shift", TCKN_SPAN, "28.02.2024", 2).text).toBe(
      "01.03.2024",
    );
  });
});
