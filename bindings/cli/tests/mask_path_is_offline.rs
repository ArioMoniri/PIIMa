//! Structural proof that no clinical document can be in memory while this
//! binary is capable of opening a socket.
//!
//! WHY this is a source-text test and not a behavioural one: a behavioural test
//! ("we observed no packets") can only sample the paths it happened to exercise,
//! and the dangerous path is by definition the one nobody thought to exercise.
//! What is asserted here is stronger and cheaper: the module that handles
//! documents cannot NAME the modules that talk to the network, and the dispatch
//! arm that calls it does not either. A future edit that reintroduces the
//! coupling fails this test at compile-check time, before anyone has to reason
//! about statement ordering.
//!
//! If this test ever needs to be relaxed, it does not. Move the network call to
//! process start instead.

/// Every module that can hold a clinical document in memory.
///
/// `batch.rs` and `format.rs` were added with the directory processor and the
/// output formats. Both read documents -- `batch` reads a whole tree of them --
/// so both are on exactly the same footing as `mask.rs`, and a scan that covered
/// only `mask.rs` would have grown a hole the moment the batch path landed.
/// `maskfile.rs` joined them with `deid mask-file`, which reads PDFs and DOCX
/// files: the same footing again, and the same reason the list is enumerated
/// here rather than inferred.
///
/// `l3.rs` joined them with the Expert Determination wiring. It never holds the
/// document itself -- the prompt is built in `core/` and delivered on stdin by
/// `bindings/llm` -- but it is ON the path that does, and a module that
/// constructs the contextual layer is exactly where somebody would one day add
/// "fetch the weights if they are missing".
const DOCUMENT_MODULES: [(&str, &str); 5] = [
    ("src/mask.rs", include_str!("../src/mask.rs")),
    ("src/batch.rs", include_str!("../src/batch.rs")),
    ("src/format.rs", include_str!("../src/format.rs")),
    ("src/maskfile.rs", include_str!("../src/maskfile.rs")),
    ("src/l3.rs", include_str!("../src/l3.rs")),
];

const MAIN: &str = include_str!("../src/main.rs");

/// Source with comment lines removed.
///
/// WHY: a comment cannot open a socket, and the header of `src/mask.rs` has to be
/// able to NAME the modules it is forbidden to reach — a rule that cannot be
/// written down next to the code it governs is a rule that gets forgotten. Only
/// executable lines are scanned.
fn code_of(source: &str) -> String {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Every module in this crate that can produce network traffic.
const NETWORKING: [&str; 3] = ["update", "transport", "reqwest"];

#[test]
fn no_document_module_can_name_any_networking_module() {
    for (name, source) in DOCUMENT_MODULES {
        let code = code_of(source);
        for module in NETWORKING {
            assert!(
                !code.contains(module),
                "{name} references `{module}`. The masking path holds clinical text \
                 in memory; nothing reachable from it may open a socket (I1)."
            );
        }
    }
}

#[test]
fn no_document_module_opens_a_socket_or_imports_a_client() {
    for (name, source) in DOCUMENT_MODULES {
        let code = code_of(source);
        for banned in ["TcpStream", "TcpListener", "UdpSocket", "std::net"] {
            assert!(
                !code.contains(banned),
                "{name} references `{banned}`, which is a socket by another name."
            );
        }
    }
}

/// EVERY document-handling dispatch arm in `main.rs`, as one slice.
///
/// Extracted by slicing from the first `Command::Mask` arm in the dispatch match
/// to the `Command::Update` arm rather than by parsing. There are now four such
/// arms -- batch, single document, the refusal when both are given, and
/// `mask-file` -- and anchoring on one of them by its exact field list is what
/// broke when the second was added. The match is written with every document arm
/// immediately before `Update` for exactly this reason, and a reorder that
/// breaks the slice fails the assertion below rather than silently passing.
fn mask_dispatch_arms() -> &'static str {
    let dispatch = MAIN
        .find("match command {")
        .expect("the dispatch match must exist");
    let start = dispatch
        + MAIN[dispatch..]
            .find("Command::Mask {")
            .expect("a Mask dispatch arm must exist");
    let end = MAIN[start..]
        .find("Command::Update =>")
        .expect("the Update arm must follow every document arm; see this test's comment");
    &MAIN[start..start + end]
}

#[test]
fn no_mask_dispatch_arm_ever_calls_the_updater() {
    let arm = mask_dispatch_arms();
    // The slice really does span all three arms, or the scan below is checking
    // one arm and claiming three.
    assert_eq!(
        arm.matches("Command::Mask {").count(),
        3,
        "the mask dispatch arms moved; this scan is no longer covering all of them"
    );
    assert_eq!(
        arm.matches("Command::MaskFile {").count(),
        1,
        "the mask-file dispatch arm moved out of the scanned slice; it reads PDFs \
         and DOCX files and is on the same footing as the mask arms"
    );
    for module in NETWORKING {
        assert!(
            !arm.contains(&format!("{module}::")),
            "a document dispatch arm in src/main.rs calls into `{module}`."
        );
    }
    assert!(
        !arm.contains("spawn_startup_check"),
        "a document dispatch arm spawns an update check. The check is asynchronous, \
         so it would still be in flight while the note is in memory."
    );
}

#[test]
fn the_mask_arm_is_reached_before_any_check_can_be_spawned() {
    // Order matters for the arms that DO check: the startup check must never be
    // spawned unconditionally ahead of dispatch, or `mask` would inherit it.
    let dispatch = MAIN.find("match command {").expect("dispatch must exist");
    let unconditional = MAIN[..dispatch].contains("spawn_startup_check(&config)");
    assert!(
        !unconditional,
        "an update check is spawned before dispatch, so it applies to `deid mask` too."
    );
}
