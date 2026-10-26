#[cfg(windows)]
fn main() {
    const TEST_PASSWORD: &str = "Testnet8-Windows-NoEcho-Password";
    let password = rpassword::prompt_password("Windows hidden-password smoke test: ")
        .expect("Windows console password prompt must be readable");
    assert_eq!(password, TEST_PASSWORD, "ConPTY input must reach rpassword");
    println!("WINDOWS_PASSWORD_PROMPT_OK");
}

#[cfg(not(windows))]
fn main() {
    eprintln!("This smoke-test example is intended for native Windows CI.");
}
