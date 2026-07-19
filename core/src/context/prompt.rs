//! The L3 prompt: what the local model is asked, and in what shape.
//!
//! TWO DESIGN DECISIONS DOMINATE THIS FILE.
//!
//! First, THE MODEL IS ASKED FOR A VERBATIM QUOTE AND NEVER FOR AN OFFSET.
//! Language models are arithmetic-free over their own token stream: a model
//! that reads a phrase correctly still reports its character position wrong,
//! and in Turkish it is wrong twice over, because `ş`, `ğ` and `İ` are two
//! bytes each so even a correct CHARACTER index is the wrong BYTE offset. A
//! wrong offset masks the wrong bytes, which corrupts the note and leaves the
//! identifier standing. A quote, by contrast, can be checked: `anchor.rs`
//! re-locates it in the original text or drops it. Asking for the one thing the
//! model can be held to is what makes the layer auditable.
//!
//! Second, THE PROMPT IS WRITTEN IN TURKISH. The target is Turkish clinical
//! narrative, quasi-identifiers are meanings rather than entities, and a model
//! reasoning about "the patient's wife is the only female judge in the
//! district" recognises the shape far more reliably when the instruction and
//! the material share a language and a register. The category ids stay in the
//! schema's English spelling because they are keys matched against
//! `eval/schema.yaml`, not prose.
//!
//! KNOWN RESIDUAL, stated rather than hidden: a hostile document can contain
//! the delimiter below and address the model directly. Nothing here prevents
//! that. What bounds the damage is architectural rather than textual -- the
//! model is local so an injected instruction has nowhere to send anything
//! (I1), and every returned quote must be found verbatim in the original text
//! before it becomes a span, so an injected instruction can at worst suppress
//! findings (a recall loss, visible to the red team) and cannot manufacture a
//! span over bytes the document does not contain.

/// Bumped whenever the wording below changes.
///
/// The recorded prompt hash pins the exact bytes sent to the model, but a bare
/// hash cannot tell a reviewer WHICH revision it corresponds to. This constant
/// is carried alongside it so an eval run names the prompt it used.
pub const PROMPT_VERSION: u32 = 1;

/// The marker that separates instructions from the clinical material.
pub const BODY_OPEN: &str = "<<<KLINIK_METIN_BASLANGIC>>>";

/// The closing marker. See the module header on document-side injection.
pub const BODY_CLOSE: &str = "<<<KLINIK_METIN_SON>>>";

/// Everything before the clinical material.
///
/// A `const` rather than a builder because the prompt is an input to a hash
/// that has to be reproducible: any per-call formatting is a way for two runs
/// of the same document to produce two different prompts, and a prompt hash
/// that moves cannot pin anything.
const INSTRUCTIONS: &str = concat!(
    "Görev: aşağıdaki Türkçe klinik metinde, hastanın yeniden kimliklendirilmesine\n",
    "yol açabilecek ANLATIYA GÖMÜLÜ dolaylı tanımlayıcıları bul.\n",
    "\n",
    "Kurallar:\n",
    "1. Ad, soyad, TCKN, telefon, adres, tarih gibi DOĞRUDAN tanımlayıcıları arama.\n",
    "   Onları başka katmanlar buluyor. Sen yalnızca anlatıya gömülü ipuçlarını ara.\n",
    "2. Tıbbi terimleri asla işaretleme: tanı, anatomi, ilaç adı ve kısaltma\n",
    "   (carcinoma, pneumonia, sinistra, metformin, MRI, PET-CT) ile bunların\n",
    "   Türkçe ekli biçimleri (carcinoma'lı, MRI'da) tıbbi kayıttır, kimlik değildir.\n",
    "3. Her bulgu için metinden BİREBİR alıntı ver. Alıntıyı harfi harfine kopyala:\n",
    "   Türkçe ekler, büyük/küçük harf, kesme işareti ve noktalama dahil hiçbir\n",
    "   karakteri değiştirme, düzeltme, kısaltma veya normalleştirme.\n",
    "4. ASLA karakter veya bayt konumu (offset, index, pozisyon) verme.\n",
    "   Yalnızca alıntı metnini ver.\n",
    "5. Emin olmadığın bir ifadeyi yine de ver: bir ipucunu kaçırmak, fazladan\n",
    "   işaretlemekten daha kötüdür.\n",
    "6. Bulgu yoksa boş dizi döndür: []\n",
    "\n",
    "Kategoriler ve örnekleri:\n",
    "EMPLOYER_ROLE        işyeri, meslek veya unvan.\n",
    "                     örnek: \"Merkez Bankası'nda müfettiş olarak çalışıyor\"\n",
    "RELATIONSHIP_REF     yakın/akraba referansı artı ayırt edici bir ayrıntı.\n",
    "                     örnek: \"eşi ilçedeki tek kadın hâkim\"\n",
    "ASSET_LOCATION       mülk veya varlık artı coğrafya.\n",
    "                     örnek: \"Bodrum'daki yazlığında kalıyor\"\n",
    "DISTINCTIVE_EVENT    kişiyi tekilleştiren olay.\n",
    "                     örnek: \"geçen yıl fabrika yangınında yaralanan tek işçi\"\n",
    "RARE_ATTRIBUTE_COMBO tek başına zararsız, birlikte tekilleştiren nitelikler.\n",
    "                     örnek: \"82 yaşında, üçüz doğum yapmış, ilçedeki tek öğretmen\"\n",
    "\n",
    "Çıktı biçimi: SADECE bir JSON dizisi döndür. Açıklama, başlık, ön söz veya\n",
    "kod bloğu ekleme. Her öğede tam olarak şu üç alan bulunsun:\n",
    "[{\"quote\": \"metinden birebir alıntı\", \"category\": \"EMPLOYER_ROLE\",\n",
    "  \"reason\": \"tek satırlık gerekçe\"}]\n",
);

/// Build the prompt for one document.
///
/// Byte-for-byte reproducible: the same document yields the same prompt, which
/// is the precondition for the prompt hash recorded in the audit trail meaning
/// anything at all.
#[must_use]
pub fn build(body: &str) -> String {
    let mut buffer = String::with_capacity(INSTRUCTIONS.len() + body.len() + 128);
    buffer.push_str(INSTRUCTIONS);
    buffer.push('\n');
    buffer.push_str(BODY_OPEN);
    buffer.push('\n');
    buffer.push_str(body);
    buffer.push('\n');
    buffer.push_str(BODY_CLOSE);
    buffer.push('\n');
    buffer
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::label::QuasiCategory;

    /// Synthetic Turkish narrative. No real PHI (I8).
    const BODY: &str = "Hasta Merkez Bankası'nda müfettiş olarak çalışıyor.";

    #[test]
    fn the_prompt_carries_the_body_verbatim_between_its_markers() {
        let prompt = build(BODY);
        let open = prompt.find(BODY_OPEN).expect("open marker");
        let close = prompt.find(BODY_CLOSE).expect("close marker");
        assert!(open < close);
        let between = prompt
            .get(open + BODY_OPEN.len()..close)
            .expect("marker offsets are char boundaries");
        assert_eq!(between.trim(), BODY);
    }

    #[test]
    fn every_quasi_category_is_named_with_an_example() {
        // A category the prompt never mentions is a category the model never
        // returns, and `parse.rs` would then be validating against a vocabulary
        // the model was never shown.
        for category in QuasiCategory::ALL {
            assert!(
                INSTRUCTIONS.contains(category.as_str()),
                "prompt does not name {category}"
            );
        }
        // One example line per category: five `ornek:` lines, no more, no less.
        assert_eq!(
            INSTRUCTIONS.matches("örnek:").count(),
            QuasiCategory::ALL.len()
        );
    }

    #[test]
    fn the_prompt_asks_for_a_quote_and_forbids_offsets() {
        // THE load-bearing instruction of this layer. If it ever disappears the
        // model starts returning integers, the anchor step starts trusting
        // them, and the pipeline masks the wrong bytes.
        assert!(INSTRUCTIONS.contains("BİREBİR alıntı"));
        assert!(INSTRUCTIONS.contains("ASLA karakter veya bayt konumu"));
        assert!(INSTRUCTIONS.contains("\"quote\""));
    }

    #[test]
    fn the_prompt_is_byte_for_byte_reproducible() {
        assert_eq!(build(BODY), build(BODY));
    }

    #[test]
    fn a_turkish_body_survives_the_prompt_unchanged() {
        // Multi-byte letters must not be normalised on the way in: the quote
        // the model returns is compared against the ORIGINAL bytes, so any
        // rewrite here makes every anchor fail.
        let turkish = "Eşi Kadıköy'deki tek kadın hâkim; yazlığı Bodrum'da.";
        assert!(build(turkish).contains(turkish));
    }

    #[test]
    fn the_empty_body_still_produces_a_well_formed_prompt() {
        let prompt = build("");
        assert!(prompt.contains(BODY_OPEN));
        assert!(prompt.contains(BODY_CLOSE));
    }
}
