#[cfg(feature = "stack_measurement")]
mod inner {
    pub use core::arch::asm;
    pub use core::sync::atomic::{AtomicUsize, Ordering};

    pub static STACK_END: AtomicUsize = AtomicUsize::new(usize::MAX);

    #[macro_export]
    macro_rules! stack_ptr {
        () => ({
            let x: usize;
            unsafe {
                asm!(
                    "mov {0}, sp" ,
                    out(reg) x,
                    options(pure, nomem, nostack),
                );
            }
            x
        })
    }

    #[macro_export]
    macro_rules! tick {
        () => {{
            let curr_rsp = stack_ptr!();
            STACK_END.fetch_min(curr_rsp, Ordering::SeqCst);
        }};
    }

    pub fn stack_usage<T, F: FnOnce() -> T>(callback: F) -> (T, usize) {
        STACK_END.store(usize::MAX, Ordering::SeqCst);
        let stack_start = stack_ptr!();

        let t = callback();

        let stack_end = STACK_END.load(Ordering::SeqCst);
        if stack_start < stack_end {
            panic!("tick!() was never called");
        }

        (t, stack_start - stack_end)
    }
}

#[cfg(not(feature = "stack_measurement"))]
mod inner {
    #[macro_export]
    macro_rules! stack_ptr {
        () => {
            0
        };
    }

    #[macro_export]
    macro_rules! tick {
        () => {};
    }
}

pub use inner::*;

#[cfg(test)]
mod test {
    use super::*;
    use crate::{stack_ptr, tick};

    fn fibonacci(n: u64) -> u64 {
        tick!();
        match n {
            0 => 0,
            1 => 1,
            _ => fibonacci(n - 1) + fibonacci(n - 2),
        }
    }

    fn fibonacci_stack(n: u64) -> usize {
        stack_usage(|| {
            let _ = fibonacci(n);
        })
        .1
    }

    #[test]
    fn stack_measurement() {
        let stack2 = fibonacci_stack(2);
        let stack3 = fibonacci_stack(3);
        let stack4 = fibonacci_stack(4);

        // Stack size should increase linearly
        assert!(stack3 > stack2);
        assert!(stack4 > stack3);
        assert_eq!(stack3 - stack2, stack4 - stack3);
    }
}
