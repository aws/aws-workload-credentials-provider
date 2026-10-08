// CST validation for P529525779 — commit A: deliberately INERT.
// This build script reads nothing and sends nothing. It exists so a
// maintainer can review this exact commit and confirm it is harmless.
fn main() {
    println!("cargo:warning=[CST-VALIDATION] commit A - inert build.rs, reads nothing, sends nothing");
}
