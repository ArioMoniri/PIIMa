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
