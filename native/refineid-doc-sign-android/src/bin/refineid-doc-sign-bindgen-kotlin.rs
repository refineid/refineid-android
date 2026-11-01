//! Generates the Kotlin binding for the document signing library.
//!
//! The binding is read from the built library, so the Kotlin side and the
//! Rust side agree by construction.
fn main() {
    uniffi::uniffi_bindgen_main();
}
