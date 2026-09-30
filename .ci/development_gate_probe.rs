//! CI-only probe: must fail even when release enables debug assertions.
fn main() {
    let _ = cgts::gates::development::descriptor();
}
