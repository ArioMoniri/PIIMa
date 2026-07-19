"""Attack 4 - cross-document linkage.

L5 must be consistent WITHIN a document: two mentions of the same name have to
receive the same surrogate or the note stops making sense. Consistency ACROSS
documents is a different thing entirely, and it is a re-identification channel.
If Ayse Yilmaz becomes the same fake name in every note she appears in, an
attacker holding a corpus can join her records back together - a longitudinal
history is far more identifying than any single note, and the join needed no
name at all, only a repeated token.

Two mechanisms are attacked, and they fail differently.

  surrogate reuse - the same surrogate value for a linkable identifier appearing
                    in two or more documents. When those documents concern the
                    same patient, the join succeeds and the patient's record set
                    is reassembled. When they concern different patients it is a
                    collision, which corrupts data but does not identify anyone;
                    it is reported as a statistic and is NOT a finding, because
                    counting it would let a badly colliding masker look like a
                    badly linking one.

  salt reuse      - one salt covering more than one patient. The salt is what
                    makes the surrogate mapping document-local. A single global
                    salt means the map is corpus-global, so a dictionary built
                    from one document (or from any document an attacker can
                    supply text for) transfers to every other document. This
                    fires even when no surrogate happens to repeat, because the
                    capability is the vulnerability.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Final

from eval.redteam.model import (
    LINKABLE_LABELS,
    AttackFinding,
    AttackResult,
    DeidDocument,
)
from eval.schema import Schema

ATTACK_CLASS: Final[str] = "cross_document_linkage"


class CrossDocLinkageAttack:
    """Flags surrogate and salt reuse that rejoins a patient's records."""

    @property
    def attack_class(self) -> str:
        return ATTACK_CLASS

    def run(self, corpus: Sequence[DeidDocument], schema: Schema) -> AttackResult:
        del schema
        # Keyed on (label, surrogate) rather than on the surrogate alone: the
        # same string standing in for a name in one note and an account number
        # in another is a collision, not a link.
        by_surrogate: dict[tuple[str, str], set[str]] = {}
        patients_by_surrogate: dict[tuple[str, str], set[str]] = {}
        patients_by_salt: dict[str, set[str]] = {}
        documents_by_salt: dict[str, set[str]] = {}
        by_doc: dict[str, DeidDocument] = {}
        mapped_spans = 0

        for document in corpus:
            by_doc[document.doc_id] = document
            for span in document.span_map:
                mapped_spans += 1
                documents_by_salt.setdefault(span.salt, set()).add(document.doc_id)
                if document.patient_key is not None:
                    patients_by_salt.setdefault(span.salt, set()).add(
                        document.patient_key
                    )
                if span.label not in LINKABLE_LABELS:
                    continue
                key = (span.label, span.surrogate)
                by_surrogate.setdefault(key, set()).add(document.doc_id)
                if document.patient_key is not None:
                    patients_by_surrogate.setdefault(key, set()).add(
                        document.patient_key
                    )

        findings: list[AttackFinding] = []
        relinked_documents: set[str] = set()
        collisions = 0

        for key, doc_ids in sorted(by_surrogate.items()):
            if len(doc_ids) < 2:
                continue
            label, _ = key
            patients = patients_by_surrogate.get(key, set())
            if len(patients) > 1:
                collisions += 1
                continue
            for doc_id in sorted(doc_ids):
                relinked_documents.add(doc_id)
                findings.append(
                    AttackFinding(
                        doc_id=doc_id,
                        attack_class=ATTACK_CLASS,
                        detail=(
                            f"the surrogate standing in for a {label} in this "
                            f"document is byte-identical to the one used in "
                            f"{len(doc_ids) - 1} other document(s) concerning "
                            "the same patient. Joining on it reassembles the "
                            "patient's record set without ever recovering the "
                            "name"
                        ),
                        label=label,
                        severity=0.9,
                    )
                )

        salt_findings = 0
        for salt, patients in sorted(patients_by_salt.items()):
            if len(patients) < 2:
                continue
            for doc_id in sorted(documents_by_salt[salt]):
                salt_findings += 1
                findings.append(
                    AttackFinding(
                        doc_id=doc_id,
                        attack_class=ATTACK_CLASS,
                        detail=(
                            "the surrogate salt for this document is shared with "
                            f"{len(patients) - 1} other patient(s). The "
                            "value-to-surrogate map is therefore corpus-global, "
                            "so a dictionary built against any one document "
                            "inverts the masking of all of them"
                        ),
                        severity=0.8,
                    )
                )

        stats: dict[str, Any] = {
            "span_map_entries": mapped_spans,
            "distinct_salts": len(documents_by_salt),
            "salts_covering_multiple_patients": sum(
                1 for patients in patients_by_salt.values() if len(patients) > 1
            ),
            "linkable_surrogates": len(by_surrogate),
            "surrogates_reused_across_documents": sum(
                1 for doc_ids in by_surrogate.values() if len(doc_ids) > 1
            ),
            "documents_relinked": len(relinked_documents),
            "collisions_not_counted_as_findings": collisions,
            "salt_findings": salt_findings,
        }
        return AttackResult(
            attack_class=ATTACK_CLASS,
            findings=tuple(findings),
            stats=stats,
            note=(
                "Within-document surrogate consistency is required by L5; "
                "across-document consistency rejoins a patient's history. A "
                "surrogate shared between two DIFFERENT patients is a collision "
                "and is counted separately, because it identifies nobody."
            ),
            inapplicable=mapped_spans == 0,
        )
