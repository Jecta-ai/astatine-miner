use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

const MAX_DIAGNOSTICS: usize = 64;
const MAX_DISPLAY_BYTES: usize = 1024;

/// Encode terminal controls in untrusted display text without changing error classification.
pub(crate) fn terminal_text(text: &str) -> String {
    let mut output = String::new();
    for ch in text.chars() {
        let code = ch as u32;
        let format_control = matches!(code,
            0x00ad | 0x0600..=0x0605 | 0x061c | 0x06dd | 0x070f | 0x0890..=0x0891 |
            0x08e2 | 0x180e | 0x200b..=0x200f | 0x2028..=0x202e | 0x2060..=0x206f |
            0xfeff | 0xfff9..=0xfffb | 0x110bd | 0x110cd | 0x13430..=0x1343f |
            0x1bca0..=0x1bca3 | 0x1d173..=0x1d17a | 0xe0001 | 0xe0020..=0xe007f);
        let piece = if ch.is_control() || format_control {
            format!("\\u{{{code:x}}}")
        } else {
            ch.to_string()
        };
        if output.len() + piece.len() > MAX_DISPLAY_BYTES {
            output.push_str("…[truncated]");
            break;
        }
        output.push_str(&piece);
    }
    output
}

#[derive(Clone, Debug, Default)]
pub struct DiagnosticBuffer {
    messages: Arc<Mutex<VecDeque<String>>>,
}

impl DiagnosticBuffer {
    pub fn push(&self, message: impl Into<String>) {
        let mut messages = self
            .messages
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if messages.len() == MAX_DIAGNOSTICS {
            messages.pop_front();
        }
        messages.push_back(terminal_text(&message.into()));
    }

    pub fn latest(&self) -> Option<String> {
        self.messages
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .back()
            .cloned()
    }

    pub fn drain(&self) -> Vec<String> {
        self.messages
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain(..)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{DiagnosticBuffer, MAX_DIAGNOSTICS};

    #[test]
    fn diagnostics_remain_bounded_and_keep_the_newest_messages() {
        let diagnostics = DiagnosticBuffer::default();
        for index in 0..(MAX_DIAGNOSTICS + 2) {
            diagnostics.push(format!("event {index}"));
        }

        assert_eq!(diagnostics.latest().as_deref(), Some("event 65"));
        let messages = diagnostics.drain();
        assert_eq!(messages.len(), MAX_DIAGNOSTICS);
        assert_eq!(messages.first().map(String::as_str), Some("event 2"));
        assert_eq!(messages.last().map(String::as_str), Some("event 65"));
        assert!(diagnostics.latest().is_none());
    }

    #[test]
    fn diagnostic_queue_returns_safe_bounded_terminal_text() {
        let diagnostics = DiagnosticBuffer::default();
        diagnostics.push(format!(
            "RPC \x1b]52;c;abc\x07\r\n\u{009b}\u{202e}{}",
            "界".repeat(5000)
        ));
        let rendered = diagnostics.drain().pop().unwrap();
        assert!(!rendered.contains('\x1b') && !rendered.contains('\x07'));
        assert!(!rendered.contains('\r') && !rendered.contains('\n'));
        assert!(!rendered.contains('\u{009b}') && !rendered.contains('\u{202e}'));
        assert!(rendered.contains("truncated") && rendered.len() < 2048);
    }

    #[test]
    fn terminal_text_escapes_unicode_line_separators() {
        let text = super::terminal_text("before\u{2028}middle\u{2029}after");
        assert!(!text.contains('\u{2028}') && !text.contains('\u{2029}'));
        assert!(text.contains("\\u{2028}") && text.contains("\\u{2029}"));
    }
}
