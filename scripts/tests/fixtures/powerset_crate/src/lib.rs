//! Fixture for the powerset-accumulation regression. Each branch is a
//! distinct function so the merged LCOV's FNDA records name both.

#[cfg(feature = "fa")]
pub fn branch_with_fa() -> u8 {
    1
}

#[cfg(not(feature = "fa"))]
pub fn branch_without_fa() -> u8 {
    0
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "fa")]
    #[test]
    fn exercises_fa() {
        assert_eq!(super::branch_with_fa(), 1);
    }

    #[cfg(not(feature = "fa"))]
    #[test]
    fn exercises_not_fa() {
        assert_eq!(super::branch_without_fa(), 0);
    }
}
