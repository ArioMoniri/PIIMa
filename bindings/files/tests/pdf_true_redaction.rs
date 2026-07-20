//! The adversarial PDF suite: an identifier hidden in every place a real
//! redaction failure has hidden one, plus the two cases the tool must REFUSE.
//!
//! Every fixture is built here, at runtime, from a checksum-valid TCKN that is
//! computed rather than written down (I8). Nothing in this file is real PHI.
//!
//! These are integration tests on purpose. They drive `redact` through its
//! public surface and then inspect the OUTPUT BYTES, which is the only vantage
//! point from which "the text was removed" is a checkable claim rather than an
//! assertion about the redactor's own state.

use deid_tr_core::{Pipeline, Tier};
use deid_tr_files::pdf::{self, PdfError};
use deid_tr_files::{FileError, Masker};

/// A checksum-valid TCKN, built at runtime. Never committed as a literal (I8).
fn tckn() -> String {
    let prefix = [1u8, 2, 3, 4, 5, 6, 7, 8, 9];
    let digit = |i: usize| u32::from(prefix[i]);
    let odd = digit(0) + digit(2) + digit(4) + digit(6) + digit(8);
    let even = digit(1) + digit(3) + digit(5) + digit(7);
    let tenth = ((odd * 7 + 1000) - even) % 10;
    let eleventh = (odd + even + tenth) % 10;
    let mut out: String = prefix.iter().map(|d| char::from(b'0' + d)).collect();
    out.push(char::from(b'0' + u8::try_from(tenth).unwrap_or(0)));
    out.push(char::from(b'0' + u8::try_from(eleventh).unwrap_or(0)));
    out
}

fn masker() -> Masker<'static> {
    Masker::new(Box::leak(Box::new(Pipeline::new(Tier::SafeHarbor))))
}

/// Assemble a PDF from object bodies.
///
/// The cross-reference table is deliberately a stub: the loader SCANS for
/// objects rather than trusting the xref (see `document.rs`), and a fixture
/// that hand-computes offsets would be testing the fixture builder.
fn build(objects: &[(u32, String)], trailer: &str) -> Vec<u8> {
    let mut out = String::from("%PDF-1.7\n");
    for (number, body) in objects {
        out.push_str(&format!("{number} 0 obj\n{body}\nendobj\n"));
    }
    out.push_str("xref\n0 1\n0000000000 65535 f \n");
    out.push_str(&format!("trailer\n{trailer}\nstartxref\n0\n%%EOF\n"));
    out.into_bytes()
}

fn stream(body: &str) -> String {
    format!("<< /Length {} >>\nstream\n{body}\nendstream", body.len())
}

/// A one-page document with the identifier in FIVE places at once.
fn everywhere(token: &str) -> Vec<u8> {
    build(
        &[
            (
                1,
                "<< /Type /Catalog /Pages 2 0 R /Outlines 6 0 R /Metadata 10 0 R >>".to_owned(),
            ),
            (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_owned()),
            (
                3,
                "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 5 0 R >> >> \
                 /Contents 4 0 R /Annots [7 0 R] >>"
                    .to_owned(),
            ),
            (
                4,
                stream(&format!(
                    "BT /F1 12 Tf 72 720 Td (TCKN {token} kayitli) Tj ET"
                )),
            ),
            (
                5,
                "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_owned(),
            ),
            (6, "<< /Type /Outlines /First 8 0 R /Count 1 >>".to_owned()),
            (
                7,
                format!(
                    "<< /Type /Annot /Subtype /Text /Contents (TCKN {token}) /Rect [0 0 10 10] >>"
                ),
            ),
            (8, format!("<< /Title (Hasta {token}) /Parent 6 0 R >>")),
            (9, format!("<< /Title (Rapor {token}) /Author (Dr X) >>")),
            (
                10,
                stream(&format!(
                    "<?xpacket?><x:xmpmeta><dc:title>{token}</dc:title></x:xmpmeta>"
                )),
            ),
        ],
        "<< /Size 11 /Root 1 0 R /Info 9 0 R >>",
    )
}

#[test]
fn the_identifier_is_gone_from_body_metadata_annotation_bookmark_and_xmp() {
    // THE headline test. Each of these five locations is a documented
    // real-world leak: body text (Manafort), the Info dictionary, annotation
    // contents, bookmark titles (AstraZeneca) and the XMP packet.
    let token = tckn();
    let input = everywhere(&token);
    assert!(
        input.windows(11).any(|w| w == token.as_bytes()),
        "the fixture must actually contain the identifier"
    );

    let redaction = pdf::redact(&masker(), &input).expect("redaction");
    assert!(
        !redaction.bytes.windows(11).any(|w| w == token.as_bytes()),
        "the identifier survived somewhere in the output"
    );
    assert!(redaction.removed_from_pages >= 1);
    assert_eq!(redaction.pages, 1);
    for key in ["/Metadata", "/Outlines", "/Info"] {
        assert!(
            !String::from_utf8_lossy(&redaction.bytes).contains(key),
            "{key} survived"
        );
    }
}

#[test]
fn a_black_rectangle_over_the_text_is_not_accepted_as_a_redaction() {
    // The failure this module exists to prevent, made into a test. The fixture
    // paints an opaque box over the identifier the way a naive tool would, and
    // leaves the glyph codes in place. The tool must still REMOVE them.
    let token = tckn();
    let covered =
        format!("0 0 0 rg 70 715 200 20 re f BT /F1 12 Tf 72 720 Td (TCKN {token}) Tj ET");
    let input = build(
        &[
            (1, "<< /Type /Catalog /Pages 2 0 R >>".to_owned()),
            (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_owned()),
            (
                3,
                "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>".to_owned(),
            ),
            (4, stream(&covered)),
            (5, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_owned()),
        ],
        "<< /Size 6 /Root 1 0 R >>",
    );
    let redaction = pdf::redact(&masker(), &input).expect("redaction");
    assert!(!redaction.bytes.windows(11).any(|w| w == token.as_bytes()));
    // The rectangle itself is left alone: this crate removes text, it does not
    // second-guess the page's graphics.
    assert!(String::from_utf8_lossy(&redaction.bytes).contains("re f"));
}

#[test]
fn a_previous_revision_does_not_survive_an_incremental_update() {
    // THE most common catastrophic failure. The first revision carries the
    // identifier; a later save replaced it. Nothing in the CURRENT revision
    // contains the identifier, so the masker never sees it -- the only thing
    // that removes it is the full rewrite.
    let token = tckn();
    let mut input = build(
        &[
            (1, "<< /Type /Catalog /Pages 2 0 R >>".to_owned()),
            (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_owned()),
            (
                3,
                "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>".to_owned(),
            ),
            (4, stream(&format!("BT /F1 12 Tf (TCKN {token}) Tj ET"))),
            (5, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_owned()),
        ],
        "<< /Size 6 /Root 1 0 R >>",
    );
    // The incremental save: a new body for object 4, a new xref section and a
    // trailer chained to the previous one with /Prev.
    let replacement = stream("BT /F1 12 Tf (TCKN [REDACTED]) Tj ET");
    input.extend_from_slice(
        format!(
            "4 0 obj\n{replacement}\nendobj\nxref\n0 1\n0000000000 65535 f \n\
             trailer\n<< /Size 6 /Root 1 0 R /Prev 0 >>\nstartxref\n0\n%%EOF\n"
        )
        .as_bytes(),
    );
    assert!(
        input.windows(11).any(|w| w == token.as_bytes()),
        "the fixture must carry its own history"
    );

    let redaction = pdf::redact(&masker(), &input).expect("redaction");
    assert_eq!(
        redaction.input_revisions, 2,
        "the fixture must be recognised as incrementally saved"
    );
    assert!(
        !redaction.bytes.windows(11).any(|w| w == token.as_bytes()),
        "the pre-redaction revision survived into the output"
    );
    assert_eq!(
        redaction
            .bytes
            .windows(5)
            .filter(|w| *w == b"%%EOF")
            .count(),
        1
    );
    assert!(!String::from_utf8_lossy(&redaction.bytes).contains("/Prev"));
    // And the CURRENT revision's text is the one that came through.
    assert!(String::from_utf8_lossy(&redaction.bytes).contains("[REDACTED]"));
}

#[test]
fn a_scanned_page_is_refused_by_number_rather_than_passed_through() {
    // A page whose only content is an image. There is no text to remove, this
    // crate has no OCR, and returning the file would hand back something that
    // looks processed and is not.
    let input = build(
        &[
            (1, "<< /Type /Catalog /Pages 2 0 R >>".to_owned()),
            (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_owned()),
            (
                3,
                "<< /Type /Page /Parent 2 0 R /Resources << /XObject << /Im0 4 0 R >> >> /Contents 5 0 R >>".to_owned(),
            ),
            (
                4,
                "<< /Type /XObject /Subtype /Image /Width 8 /Height 8 /Length 4 >>\nstream\n\x00\x01\x02\x03\nendstream".to_owned(),
            ),
            (5, stream("q 612 0 0 792 0 0 cm /Im0 Do Q")),
        ],
        "<< /Size 6 /Root 1 0 R >>",
    );
    assert!(matches!(
        pdf::redact(&masker(), &input),
        Err(FileError::Pdf(PdfError::ScannedPage { page: 1 }))
    ));
}

#[test]
fn a_scan_with_an_invisible_ocr_text_layer_is_refused() {
    // The nastiest case: `3 Tr` text drawn over a scan. Redacting the text
    // layer would produce a file that passes every text-extraction check while
    // the identifier is still visible in the pixels.
    let token = tckn();
    let input = build(
        &[
            (1, "<< /Type /Catalog /Pages 2 0 R >>".to_owned()),
            (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_owned()),
            (
                3,
                "<< /Type /Page /Parent 2 0 R /Resources << /XObject << /Im0 4 0 R >> \
                 /Font << /F1 6 0 R >> >> /Contents 5 0 R >>"
                    .to_owned(),
            ),
            (
                4,
                "<< /Type /XObject /Subtype /Image /Width 8 /Height 8 /Length 4 >>\nstream\n\x00\x01\x02\x03\nendstream".to_owned(),
            ),
            (
                5,
                stream(&format!(
                    "q 612 0 0 792 0 0 cm /Im0 Do Q BT 3 Tr /F1 12 Tf (TCKN {token}) Tj ET"
                )),
            ),
            (6, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_owned()),
        ],
        "<< /Size 7 /Root 1 0 R >>",
    );
    assert!(matches!(
        pdf::redact(&masker(), &input),
        Err(FileError::Pdf(PdfError::ScannedWithTextLayer { page: 1 }))
    ));
}

#[test]
fn an_encrypted_pdf_is_refused_rather_than_passed_through() {
    let input = build(
        &[
            (1, "<< /Type /Catalog /Pages 2 0 R >>".to_owned()),
            (2, "<< /Type /Pages /Kids [] /Count 0 >>".to_owned()),
        ],
        "<< /Size 3 /Root 1 0 R /Encrypt 9 0 R >>",
    );
    assert!(matches!(
        pdf::redact(&masker(), &input),
        Err(FileError::Pdf(PdfError::Encrypted))
    ));
}

#[test]
fn verification_catches_a_file_where_the_text_was_only_covered_up() {
    // The verifier is exercised directly against a file that was NOT produced
    // by this crate, which is the only way to show it would have caught the
    // failure rather than merely agreeing with the redactor.
    let token = tckn();
    let fake = build(
        &[
            (1, "<< /Type /Catalog /Pages 2 0 R >>".to_owned()),
            (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_owned()),
            (
                3,
                "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>".to_owned(),
            ),
            (
                4,
                stream(&format!("0 0 0 rg 70 715 200 20 re f BT /F1 12 Tf (TCKN {token}) Tj ET")),
            ),
            (5, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_owned()),
        ],
        "<< /Size 6 /Root 1 0 R >>",
    );
    let failure = pdf::verify(&fake, std::slice::from_ref(&token)).expect_err("must not verify");
    assert!(matches!(
        failure,
        pdf::VerificationFailure::IdentifierSurvived { index: 0, .. }
    ));
    // And the failure message must not repeat the identifier back (I4).
    assert!(!format!("{failure}").contains(&token));
}

#[test]
fn a_document_with_nothing_to_redact_still_round_trips_and_verifies() {
    let input = build(
        &[
            (1, "<< /Type /Catalog /Pages 2 0 R >>".to_owned()),
            (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_owned()),
            (
                3,
                "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>".to_owned(),
            ),
            (4, stream("BT /F1 12 Tf (Hasta Ayse Yilmaz muayene edildi) Tj ET")),
            (5, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_owned()),
        ],
        "<< /Size 6 /Root 1 0 R >>",
    );
    let redaction = pdf::redact(&masker(), &input).expect("redaction");
    assert_eq!(redaction.removed_from_pages, 0);
    // THE HONESTY ASSERTION. No model is installed, so the name is still on the
    // page. If this ever starts failing because a name IS removed, every doc
    // string and CLI line promising otherwise has to change with it.
    assert!(String::from_utf8_lossy(&redaction.bytes).contains("Ayse Yilmaz"));
}

#[test]
fn extraction_reads_the_same_page_the_redactor_reads() {
    // The display path and the redaction path share `read_page`, and this is the
    // assertion that keeps them shared. A surface that SHOWS a reader extracted
    // text before handing back bytes they cannot inspect is only honest if the
    // text shown is the text scanned -- so the token the redactor removed must
    // be present, at that page number, in what extraction returns.
    let token = tckn();
    let pages = pdf::extract_pages(&everywhere(&token)).expect("extract");
    assert_eq!(pages.len(), 1);
    assert_eq!(pages[0].page, 1);
    assert!(pages[0].text.contains(&token));
    // And redaction of the same bytes removes exactly that token, which is what
    // makes the previous assertion a claim about the pipeline rather than about
    // a second, similar-looking decoder.
    let redaction = pdf::redact(&masker(), &everywhere(&token)).expect("redact");
    assert!(!String::from_utf8_lossy(&redaction.bytes).contains(&token));
}

#[test]
fn extraction_refuses_a_scanned_page_by_number_exactly_as_redaction_does() {
    // A surface that displays before redacting must learn about a refusal at
    // DISPLAY time. If extraction were permissive here it would render an empty
    // page as "nothing found on page 1" and the reader would conclude the scan
    // was clean, which is the vacuous-pass failure the whole module exists to
    // refuse.
    let input = build(
        &[
            (1, "<< /Type /Catalog /Pages 2 0 R >>".to_owned()),
            (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_owned()),
            (
                3,
                "<< /Type /Page /Parent 2 0 R /Resources << /XObject << /Im0 4 0 R >> >> /Contents 5 0 R >>".to_owned(),
            ),
            (
                4,
                "<< /Type /XObject /Subtype /Image /Width 8 /Height 8 /Length 4 >>\nstream\n\x00\x01\x02\x03\nendstream".to_owned(),
            ),
            (5, stream("q 612 0 0 792 0 0 cm /Im0 Do Q")),
        ],
        "<< /Size 6 /Root 1 0 R >>",
    );
    assert!(matches!(
        pdf::extract_pages(&input),
        Err(FileError::Pdf(PdfError::ScannedPage { page: 1 }))
    ));
}

#[test]
fn page_text_debug_never_prints_the_page() {
    // I4. `PageText` is the one type in this module that carries document text,
    // so its `Debug` is hand-written. A derive added here later would put a
    // clinical page into the first `{:?}` that touches it, and this test is what
    // would catch that.
    let token = tckn();
    let pages = pdf::extract_pages(&everywhere(&token)).expect("extract");
    let rendered = format!("{:?}", pages[0]);
    assert!(!rendered.contains(&token));
    assert!(rendered.contains("redacted"));
}

/// A one-page document whose text is drawn by a simple font with
/// `/WinAnsiEncoding` and no `/Differences`.
///
/// The six bytes are written as PDF octal escapes so this file stays ASCII: a
/// test fixture whose meaning depends on the editor's own encoding is a test
/// that can pass for the wrong reason.
fn winansi_turkish() -> Vec<u8> {
    build(
        &[
            (1, "<< /Type /Catalog /Pages 2 0 R >>".to_owned()),
            (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_owned()),
            (
                3,
                "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 5 0 R >> >> \
                 /Contents 4 0 R >>"
                    .to_owned(),
            ),
            (
                4,
                stream(r"BT /F1 12 Tf 72 720 Td (\320\335\336\360\375\376) Tj ET"),
            ),
            (
                5,
                "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica \
                 /Encoding /WinAnsiEncoding >>"
                    .to_owned(),
            ),
        ],
        "<< /Size 6 /Root 1 0 R >>",
    )
}

#[test]
fn a_simple_font_decodes_turkish_through_windows_1254_not_latin1() {
    // The bug this replaces: bytes 0xD0 0xDD 0xDE 0xF0 0xFD 0xFE decoded through
    // `char::from_u32`, which is Latin-1, so every Turkish letter in a Turkish
    // report was corrupted BEFORE detection ever ran. `Şükrü` reaching the rules
    // layer as `Þükrü` is a different string, which makes the code page a RECALL
    // decision (I2), not a cosmetic one.
    let pages = pdf::extract_pages(&winansi_turkish()).expect("extract");
    let text = pages[0].text.clone();
    assert!(
        text.contains("ĞİŞğış"),
        "the six Turkish letters did not round-trip"
    );
    assert!(
        !text.contains('Ð') && !text.contains('ý') && !text.contains('þ'),
        "Latin-1 mojibake survived the decode"
    );
}

/// A `/ToUnicode` CMap mapping codes `0x11..=0x1A` to the digits `0..=9`.
fn digit_cmap() -> String {
    stream(
        "/CIDInit /ProcSet findresource begin\n\
         1 begincodespacerange <0000> <FFFF> endcodespacerange\n\
         1 beginbfrange\n<0011> <001A> <0030>\nendbfrange\n\
         1 beginbfchar\n<0030> <015F>\nendbfchar\n",
    )
}

/// A one-page document whose ENTIRE body lives in a Form XObject, drawn with a
/// Type0 font declared in the form's own `/Resources`.
///
/// This is the shape HiQPdf and the Crystal/Telerik lineage emit, and it is the
/// shape that made `/ToUnicode` unreachable: the page stream is a `Do`, the
/// text and the fonts are one level down, and a reader that stops at
/// `/Contents` finds an empty page and reports it clean.
fn text_inside_a_form(token: &str) -> Vec<u8> {
    let codes: String = token
        .chars()
        .filter_map(|digit| digit.to_digit(10))
        .map(|digit| format!("{:04X}", 0x11 + digit))
        .collect();
    build(
        &[
            (1, "<< /Type /Catalog /Pages 2 0 R >>".to_owned()),
            (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_owned()),
            (
                3,
                "<< /Type /Page /Parent 2 0 R /Contents 4 0 R /Resources \
                 << /XObject << /Fm1 5 0 R >> >> >>"
                    .to_owned(),
            ),
            (4, stream("q 1 0 0 1 0 0 cm /Fm1 Do Q")),
            (
                5,
                format!(
                    "<< /Type /XObject /Subtype /Form /BBox [0 0 595 842] /Resources \
                     << /Font << /T0 6 0 R >> >> /Length {len} >>\nstream\n{body}\nendstream",
                    body = format_args!("BT /T0 12 Tf 72 720 Td <0030{codes}> Tj ET"),
                    len = 34 + codes.len(),
                ),
            ),
            (
                6,
                "<< /Type /Font /Subtype /Type0 /BaseFont /AAAAAA+Tahoma \
                 /Encoding /Identity-H /DescendantFonts [8 0 R] /ToUnicode 7 0 R >>"
                    .to_owned(),
            ),
            (7, digit_cmap()),
            (
                8,
                "<< /Type /Font /Subtype /CIDFontType2 /BaseFont /AAAAAA+Tahoma \
                 /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> >>"
                    .to_owned(),
            ),
        ],
        "<< /Size 9 /Root 1 0 R >>",
    )
}

#[test]
fn a_type0_font_in_a_form_xobject_has_its_tounicode_applied() {
    // Before, the form's stream was never read, so this page extracted to
    // nothing and redaction reported a clean document over an identifier it had
    // not looked at. The `ş` in front of the number is the second half of the
    // claim: the form's OWN font table is what decoded it.
    let token = tckn();
    let pages = pdf::extract_pages(&text_inside_a_form(&token)).expect("extract");
    let text = pages[0].text.clone();
    assert!(
        text.contains(&token),
        "the identifier inside the form was never read"
    );
    assert!(
        text.contains('ş'),
        "the form's own /ToUnicode was not applied"
    );
}

#[test]
fn an_identifier_inside_a_form_xobject_is_actually_removed() {
    // Reading it is not redacting it. The edit has to land in the FORM's stream
    // object, which is a different object from the page's `/Contents`.
    let token = tckn();
    let redaction = pdf::redact(&masker(), &text_inside_a_form(&token)).expect("redaction");
    assert!(redaction.removed_from_pages >= 1);
    assert!(
        !redaction.bytes.windows(11).any(|w| w == token.as_bytes()),
        "the identifier survived"
    );
}

#[test]
fn a_type0_font_in_a_form_with_no_tounicode_is_refused_not_emitted_as_garbage() {
    // The policy this module already states for the page, now enforced one level
    // down: undecodable CID codes are glyph-ID NOISE, and emitting them means
    // every identifier in that font is invisible to detection while the file
    // looks processed.
    let token = tckn();
    let mut objects = text_inside_a_form(&token);
    // Drop the /ToUnicode reference, leaving a Type0 font with no published
    // inverse.
    let without = String::from_utf8_lossy(&objects).replace("/ToUnicode 7 0 R ", "");
    objects = without.into_bytes();
    assert!(matches!(
        pdf::extract_pages(&objects),
        Err(FileError::Pdf(PdfError::UnreadablePage { page: 1, .. }))
    ));
}

/// A page with a REAL TEXT LAYER and images sitting in it.
///
/// This is the shape of ordinary Turkish hospital output -- a typed report
/// carrying a QR or barcode with the protokol number and a scanned signature --
/// and it is the case that used to be processed, reported as a success, and
/// returned with every pixel intact. The two 102x102 and two 320x38 sizes are
/// taken from a measured sample.
fn text_page_with_images(token: &str) -> Vec<u8> {
    build(
        &[
            (1, "<< /Type /Catalog /Pages 2 0 R >>".to_owned()),
            (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_owned()),
            (
                3,
                "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 5 0 R >> \
                 /XObject << /Im0 6 0 R /Im1 7 0 R >> >> /Contents 4 0 R >>"
                    .to_owned(),
            ),
            (
                4,
                stream(&format!(
                    "BT /F1 12 Tf 72 720 Td (TCKN {token} kayitli) Tj ET \
                     q 102 0 0 102 60 60 cm /Im0 Do Q q 320 0 0 38 60 200 cm /Im1 Do Q"
                )),
            ),
            (
                5,
                "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_owned(),
            ),
            (
                6,
                "<< /Type /XObject /Subtype /Image /Width 102 /Height 102 /Length 4 >>\n\
                 stream\n\x00\x01\x02\x03\nendstream"
                    .to_owned(),
            ),
            (
                7,
                "<< /Type /XObject /Subtype /Image /Width 320 /Height 38 /Length 4 >>\n\
                 stream\n\x00\x01\x02\x03\nendstream"
                    .to_owned(),
            ),
        ],
        "<< /Size 8 /Root 1 0 R >>",
    )
}

#[test]
fn a_page_with_both_text_and_images_is_refused_by_default() {
    // THE GAP THIS CLOSES. The page has extractable text, so `ScannedPage` does
    // not fire; it also has images this crate cannot read, so a "success" would
    // be a file somebody believes is finished. Default policy returns no bytes.
    let token = tckn();
    let outcome = pdf::redact(&masker(), &text_page_with_images(&token));
    let Err(FileError::Pdf(PdfError::PageCarriesImages(images))) = outcome else {
        panic!("a page carrying images must be refused under the default policy");
    };
    assert_eq!(images.page, 1);
    assert_eq!(images.images.len(), 2);
    assert_eq!(images.plausible_content(), 2);
}

#[test]
fn the_refusal_names_the_page_and_every_dimension() {
    // A refusal that says only "there are images" leaves the operator with
    // nothing to check. Page number, count and pixel sizes are what turns it
    // into an instruction.
    let token = tckn();
    let Err(error) = pdf::redact(&masker(), &text_page_with_images(&token)) else {
        panic!("must be refused");
    };
    let rendered = error.to_string();
    assert!(rendered.contains("page 1"), "{rendered}");
    assert!(rendered.contains("2 image(s)"), "{rendered}");
    assert!(rendered.contains("102x102"), "{rendered}");
    assert!(rendered.contains("320x38"), "{rendered}");
    // The size split is offered as a heuristic and says so, because this crate
    // decodes no images and must not imply it knows what one holds.
    assert!(rendered.contains("HEURISTIC"), "{rendered}");
    assert!(rendered.contains("--allow-images"), "{rendered}");
}

#[test]
fn the_image_report_carries_no_document_text() {
    // I4, on the newest thing that crosses a boundary. The page contains a
    // TCKN and a name; the refusal, its Debug and the warning must be numbers
    // and dimensions and nothing else.
    let token = tckn();
    let Err(error) = pdf::redact(&masker(), &text_page_with_images(&token)) else {
        panic!("must be refused");
    };
    for rendered in [error.to_string(), format!("{error:?}")] {
        assert!(!rendered.contains(&token), "{rendered}");
        assert!(!rendered.contains("kayitli"), "{rendered}");
    }
    let redaction = pdf::redact_with(
        &masker(),
        &text_page_with_images(&token),
        pdf::ImagePolicy::Warn,
    )
    .expect("warn policy returns a file");
    let rendered = format!("{:?} {}", redaction.images, redaction.images[0]);
    assert!(!rendered.contains(&token), "{rendered}");
    assert!(!rendered.contains("kayitli"), "{rendered}");
}

#[test]
fn allowing_images_redacts_the_text_and_reports_what_it_did_not_read() {
    // The override buys continuation, NOT silence. The text is really redacted
    // and the images are really reported; a caller cannot end up with the file
    // and no statement about what was skipped.
    let token = tckn();
    let redaction = pdf::redact_with(
        &masker(),
        &text_page_with_images(&token),
        pdf::ImagePolicy::Warn,
    )
    .expect("redaction");
    assert!(
        !redaction.bytes.windows(11).any(|w| w == token.as_bytes()),
        "the TCKN survived the text layer"
    );
    assert_eq!(redaction.images.len(), 1);
    assert_eq!(redaction.images[0].page, 1);
    let sizes: Vec<String> = redaction.images[0]
        .images
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(sizes, vec!["102x102".to_owned(), "320x38".to_owned()]);
}

#[test]
fn a_text_only_page_warns_about_nothing() {
    // The other half of the claim. A page with no images must produce no
    // warning at all -- a notice that appears on every document is a notice
    // nobody reads, which would cost exactly the documents that need it.
    let token = tckn();
    let redaction = pdf::redact(&masker(), &everywhere(&token)).expect("redaction");
    assert!(redaction.images.is_empty());
    let permissive = pdf::redact_with(&masker(), &everywhere(&token), pdf::ImagePolicy::Warn)
        .expect("redaction");
    assert!(permissive.images.is_empty());
}

#[test]
fn an_image_only_page_is_still_a_scan_and_no_flag_reaches_it() {
    // THE REFUSAL THAT MUST NOT HAVE BEEN WEAKENED. A page whose text is
    // entirely pixels is unredactable, not merely unread, so `--allow-images`
    // has no effect on it: there is nothing to redact and the output would be
    // vacuously "clean".
    let input = build(
        &[
            (1, "<< /Type /Catalog /Pages 2 0 R >>".to_owned()),
            (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_owned()),
            (
                3,
                "<< /Type /Page /Parent 2 0 R /Resources << /XObject << /Im0 4 0 R >> >> /Contents 5 0 R >>".to_owned(),
            ),
            (
                4,
                "<< /Type /XObject /Subtype /Image /Width 8 /Height 8 /Length 4 >>\nstream\n\x00\x01\x02\x03\nendstream".to_owned(),
            ),
            (5, stream("q 612 0 0 792 0 0 cm /Im0 Do Q")),
        ],
        "<< /Size 6 /Root 1 0 R >>",
    );
    assert!(matches!(
        pdf::redact_with(&masker(), &input, pdf::ImagePolicy::Warn),
        Err(FileError::Pdf(PdfError::ScannedPage { page: 1 }))
    ));
}

#[test]
fn extraction_refuses_a_page_with_images_exactly_as_redaction_does() {
    // Display and redaction share `read_page` and now share this policy too. A
    // surface that showed page 1 as readable and then refused to redact it
    // would be telling a reader two different things about one page.
    let token = tckn();
    let input = text_page_with_images(&token);
    assert!(matches!(
        pdf::extract_pages(&input),
        Err(FileError::Pdf(PdfError::PageCarriesImages(_)))
    ));
    let pages = pdf::extract_pages_with(&input, pdf::ImagePolicy::Warn).expect("extract");
    // And the displayed page carries the sizes, so a surface can say what it is
    // NOT showing alongside what it is.
    assert_eq!(pages[0].images.len(), 2);
    assert_eq!(pages[0].images[0].width, 102);
}

#[test]
fn a_letterhead_inherited_from_the_page_tree_is_still_found() {
    // `/Resources` is inheritable. An image declared once on the `/Pages` node
    // and used by every page is the ordinary way a letterhead is stored, and a
    // lookup that stopped at the page would report the document as image-free.
    let token = tckn();
    let input = build(
        &[
            (1, "<< /Type /Catalog /Pages 2 0 R >>".to_owned()),
            (
                2,
                "<< /Type /Pages /Kids [3 0 R] /Count 1 /Resources << /Font << /F1 5 0 R >> \
                 /XObject << /Im0 6 0 R >> >> >>"
                    .to_owned(),
            ),
            (
                3,
                "<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>".to_owned(),
            ),
            (
                4,
                stream(&format!("BT /F1 12 Tf 72 720 Td (TCKN {token}) Tj ET")),
            ),
            (
                5,
                "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_owned(),
            ),
            (
                6,
                "<< /Type /XObject /Subtype /Image /Width 240 /Height 60 /Length 4 >>\n\
                 stream\n\x00\x01\x02\x03\nendstream"
                    .to_owned(),
            ),
        ],
        "<< /Size 7 /Root 1 0 R >>",
    );
    let Err(FileError::Pdf(PdfError::PageCarriesImages(images))) = pdf::redact(&masker(), &input)
    else {
        panic!("an inherited image must be found");
    };
    assert_eq!(images.images.len(), 1);
    assert_eq!(images.images[0].to_string(), "240x60");
}

#[test]
fn an_icon_is_reported_as_plausible_decoration_and_a_qr_sized_image_is_not() {
    // The heuristic, stated as a test so it cannot quietly change meaning. It
    // classifies SIZE and claims nothing else: both of these are still reported
    // and both still refuse.
    let icon = pdf::PageImage {
        width: 12,
        height: 12,
    };
    let code = pdf::PageImage {
        width: 102,
        height: 102,
    };
    assert!(icon.plausible_decoration());
    assert!(!code.plausible_decoration());
    // An image whose size could not be read is NEVER treated as decorative --
    // an unknown must not read as a reassuring answer.
    let unknown = pdf::PageImage::default();
    assert!(!unknown.plausible_decoration());
    assert_eq!(unknown.to_string(), "size not stated");
}
