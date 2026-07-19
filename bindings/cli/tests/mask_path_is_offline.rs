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

const MASK: &str = include_str!("../src/mask.rs");
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
fn the_mask_module_cannot_name_any_networking_module() {
    let code = code_of(MASK);
    for module in NETWORKING {
        assert!(
            !code.contains(module),
            "src/mask.rs references `{module}`. The mask path holds clinical text \
             in memory; nothing reachable from it may open a socket (I1)."
        );
    }
}

#[test]
fn the_mask_module_opens_no_socket_and_imports_no_client() {
    let code = code_of(MASK);
    for banned in ["TcpStream", "TcpListener", "UdpSocket", "std::net"] {
        assert!(
            !code.contains(banned),
            "src/mask.rs references `{banned}`, which is a socket by another name."
        );
    }
}

/// The body of the `Command::Mask` dispatch arm in `main.rs`.
///
/// Extracted by slicing between the two arm labels rather than by parsing: the
/// match is written with `Mask` immediately before `Update` for exactly this
/// reason, and a reorder that breaks the slice fails the assertion below rather
/// than silently passing.
fn mask_dispatch_arm() -> &'static str {
    let start = MAIN
        .find("Command::Mask { path, tier, opts } =>")
        .expect("the Mask dispatch arm must exist and keep its shape");
    let end = MAIN[start..]
        .find("Command::Update =>")
        .expect("the Update arm must follow the Mask arm; see this test's comment");
    &MAIN[start..start + end]
}

#[test]
fn the_mask_dispatch_arm_never_calls_the_updater() {
    let arm = mask_dispatch_arm();
    for module in NETWORKING {
        assert!(
            !arm.contains(&format!("{module}::")),
            "the Command::Mask arm in src/main.rs calls into `{module}`."
        );
    }
    assert!(
        !arm.contains("spawn_startup_check"),
        "the Command::Mask arm spawns an update check. The check is asynchronous, \
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
