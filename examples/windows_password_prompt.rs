#[cfg(windows)]
fn main() {
    use std::{
        ffi::OsStr,
        os::windows::ffi::OsStrExt,
        process, thread,
        time::{Duration, Instant},
    };
    use windows_sys::Win32::{
        Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING},
        System::Console::{
            AllocConsole, CONSOLE_SCREEN_BUFFER_INFO, COORD, FreeConsole,
            GetConsoleScreenBufferInfo, INPUT_RECORD, INPUT_RECORD_0, KEY_EVENT, KEY_EVENT_RECORD,
            KEY_EVENT_RECORD_0, ReadConsoleOutputCharacterW, WriteConsoleInputW,
        },
    };

    const TEST_PASSWORD: &str = "Testnet8-Windows-NoEcho-Password";
    const PROMPT: &str = "Windows hidden-password smoke test: ";

    struct ConsoleHandle(HANDLE);

    impl ConsoleHandle {
        fn open(path: &str, access: u32) -> Option<Self> {
            let path = OsStr::new(path)
                .encode_wide()
                .chain(Some(0))
                .collect::<Vec<_>>();
            let handle = unsafe {
                CreateFileW(
                    path.as_ptr(),
                    access,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    0,
                    INVALID_HANDLE_VALUE,
                )
            };
            if handle == INVALID_HANDLE_VALUE {
                None
            } else {
                Some(Self(handle))
            }
        }
    }

    impl Drop for ConsoleHandle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    fn console_text(output: &ConsoleHandle) -> Option<String> {
        let mut info = CONSOLE_SCREEN_BUFFER_INFO::default();
        if unsafe { GetConsoleScreenBufferInfo(output.0, &mut info) } == 0
            || info.dwSize.X <= 0
            || info.dwSize.Y <= 0
        {
            return None;
        }
        let length = u32::try_from(i32::from(info.dwSize.X) * i32::from(info.dwSize.Y)).ok()?;
        let mut buffer = vec![0_u16; length as usize];
        let mut read = 0;
        if unsafe {
            ReadConsoleOutputCharacterW(
                output.0,
                buffer.as_mut_ptr(),
                length,
                COORD { X: 0, Y: 0 },
                &mut read,
            )
        } == 0
        {
            return None;
        }
        buffer.truncate(read as usize);
        Some(String::from_utf16_lossy(&buffer))
    }

    fn key_event(character: u16, key_down: bool, virtual_key: u16) -> INPUT_RECORD {
        INPUT_RECORD {
            EventType: KEY_EVENT as u16,
            Event: INPUT_RECORD_0 {
                KeyEvent: KEY_EVENT_RECORD {
                    bKeyDown: if key_down { 1 } else { 0 },
                    wRepeatCount: 1,
                    wVirtualKeyCode: virtual_key,
                    wVirtualScanCode: 0,
                    uChar: KEY_EVENT_RECORD_0 {
                        UnicodeChar: character,
                    },
                    dwControlKeyState: 0,
                },
            },
        }
    }

    fn write_events(input: &ConsoleHandle, events: &[INPUT_RECORD]) -> bool {
        let mut written = 0;
        unsafe {
            WriteConsoleInputW(input.0, events.as_ptr(), events.len() as u32, &mut written) != 0
                && written == events.len() as u32
        }
    }

    fn press_enter(input: &ConsoleHandle) -> bool {
        write_events(
            input,
            &[
                key_event('\r' as u16, true, 0x0D),
                key_event('\r' as u16, false, 0x0D),
            ],
        )
    }

    fn inject_test_password() -> bool {
        // Feed console key events instead of redirected stdin so rpassword
        // exercises its real Windows CONIN$/CONOUT$ path.
        let console_access = GENERIC_READ | GENERIC_WRITE;
        let Some(output) = ConsoleHandle::open("CONOUT$", console_access) else {
            return false;
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if console_text(&output).is_some_and(|text| text.contains(PROMPT)) {
                break;
            }
            if Instant::now() >= deadline {
                if let Some(input) = ConsoleHandle::open("CONIN$", GENERIC_WRITE) {
                    press_enter(&input);
                }
                return false;
            }
            thread::sleep(Duration::from_millis(20));
        }
        thread::sleep(Duration::from_millis(100));

        let Some(input) = ConsoleHandle::open("CONIN$", console_access) else {
            return false;
        };
        let mut events = Vec::with_capacity(TEST_PASSWORD.len() * 2 + 2);
        for character in TEST_PASSWORD.encode_utf16() {
            events.push(key_event(character, true, 0));
            events.push(key_event(character, false, 0));
        }
        events.extend_from_slice(&[
            key_event('\r' as u16, true, 0x0D),
            key_event('\r' as u16, false, 0x0D),
        ]);
        if write_events(&input, &events) {
            true
        } else {
            press_enter(&input);
            false
        }
    }

    unsafe {
        FreeConsole();
    }
    if unsafe { AllocConsole() } == 0 {
        process::exit(10);
    }

    let input_thread = thread::spawn(inject_test_password);
    let password = rpassword::prompt_password(PROMPT);
    if !input_thread.join().unwrap_or(false) {
        process::exit(11);
    }
    let password = match password {
        Ok(password) if password == TEST_PASSWORD => password,
        _ => process::exit(12),
    };
    let Some(output) = ConsoleHandle::open("CONOUT$", GENERIC_READ) else {
        process::exit(13);
    };
    let Some(text) = console_text(&output) else {
        process::exit(14);
    };
    if !text.contains(PROMPT) {
        process::exit(15);
    }
    if text.contains(password.as_str()) {
        process::exit(16);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("This smoke-test example is intended for native Windows CI.");
}
