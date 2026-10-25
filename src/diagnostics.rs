use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

const MAX_DIAGNOSTICS: usize = 64;

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
        messages.push_back(message.into());
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
}
