//! Raw-pointer boundary for the Cryptol Keccak-p FFI.

use super::{Keccak_p, State};

/// FFI entrypoint for the `Keccak-p` function, specialized to `w = 64`.
///
/// Null and misaligned pointers are rejected before memory access. The input
/// state is copied into local storage before the output is written, so input
/// and output storage may overlap, including exact in-place use.
///
/// # Safety
///
/// For non-null, properly aligned pointers:
///
/// - `A_in` must be valid for reads of one initialized `State`.
/// - `A_out` must be valid for writes of one `State`.
/// - The pointed-to storage must permit those reads and writes under Rust's
///   aliasing and provenance rules for the duration of the call.
///
/// The two FFI pointers may overlap each other because the complete input is
/// copied before the output write. Null or misaligned pointers are rejected
/// before either pointer is read or written.
#[export_name = "Keccak_p_FFI"]
pub unsafe extern "C" fn Keccak_p_FFI(A_in: *const State, A_out: *mut State) {
    if A_in.is_null() || A_out.is_null() {
        return;
    }

    if !A_in.is_aligned() || !A_out.is_aligned() {
        return;
    }

    // SAFETY: The caller guarantees that the accepted input pointer is
    // readable, aligned, initialized, and valid for one State.
    let mut state = unsafe { A_in.read() };

    Keccak_p(&mut state);

    // SAFETY: The caller guarantees that the accepted output pointer is
    // writable, aligned, and valid for one State. The input has already been
    // copied into local storage, so overlapping FFI input/output is safe.
    unsafe { A_out.write(state) };
}

#[cfg(test)]
mod tests {
    use super::Keccak_p_FFI;
    use crate::{Keccak_p, State};
    use std::ptr::{addr_of_mut, null, null_mut};

    fn sample_state() -> State {
        [
            [0, 1, 2, 3, 4],
            [5, 6, 7, 8, 9],
            [10, 11, 12, 13, 14],
            [15, 16, 17, 18, 19],
            [20, 21, 22, 23, 24],
        ]
    }

    #[test]
    fn rejects_null_pointers_before_memory_access() {
        // SAFETY: Null pointers are explicitly rejected before memory access.
        unsafe { Keccak_p_FFI(null(), null_mut()) };

        let input = sample_state();
        // SAFETY: The null output pointer is rejected before memory access.
        unsafe { Keccak_p_FFI(&input, null_mut()) };

        let mut output = [[0u64; 5]; 5];
        // SAFETY: The null input pointer is rejected before memory access.
        unsafe { Keccak_p_FFI(null(), &mut output) };
    }

    #[test]
    fn rejects_misaligned_pointers_before_memory_access() {
        let mut state = sample_state();
        let base = addr_of_mut!(state).cast::<u8>();

        // SAFETY: Adding one byte stays within the State allocation. The
        // resulting pointer is intentionally misaligned and is rejected by
        // the FFI before any read or write occurs.
        let misaligned = unsafe { base.add(1).cast::<State>() };

        // SAFETY: Misaligned pointers are explicitly rejected before memory
        // access by the function contract.
        unsafe { Keccak_p_FFI(misaligned.cast_const(), misaligned) };
    }

    #[test]
    fn preserves_separate_input_and_output_semantics() {
        let input = sample_state();
        let original_input = input;
        let mut expected = input;
        Keccak_p(&mut expected);

        let mut output = [[0u64; 5]; 5];

        // SAFETY: Both pointers refer to live, aligned State objects for the
        // duration of the call, and no conflicting aliases are used.
        unsafe { Keccak_p_FFI(&input, &mut output) };

        assert_eq!(input, original_input);
        assert_eq!(output, expected);
    }

    #[test]
    fn supports_exact_in_place_input_and_output() {
        let mut state = sample_state();
        let mut expected = state;
        Keccak_p(&mut expected);

        let state_ptr = addr_of_mut!(state);

        // SAFETY: state_ptr is live, aligned, readable, and writable for one
        // State. The implementation copies the input before writing output, so
        // exact in-place use is supported without aliased Rust references.
        unsafe { Keccak_p_FFI(state_ptr.cast_const(), state_ptr) };

        assert_eq!(state, expected);
    }
}
