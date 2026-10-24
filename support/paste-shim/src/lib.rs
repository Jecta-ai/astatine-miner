#[doc(hidden)]
pub use pastey as __private;

#[macro_export]
macro_rules! paste {
    ($($tokens:tt)*) => {
        $crate::__private::paste! { $($tokens)* }
    };
}
