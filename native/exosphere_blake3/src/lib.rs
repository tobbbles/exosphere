//! BLAKE3 for Exosphere, over the upstream `blake3` crate.
//!
//! The upstream Elixir binding (`:blake3` on Hex) only exposes the fixed
//! 32-byte digest. `Exosphere.ATProto.Spaces.Lthash` needs BLAKE3's
//! *extendable output* (XOF): every set element is expanded to 2048 bytes and
//! folded into 1024 little-endian `u16` lanes. This crate binds
//! `Hasher::finalize_xof()` for that, and adds a fused lane fold so a single
//! LtHash update is one NIF call rather than an expansion plus 1024 lane
//! operations back in Elixir.

use rustler::{Binary, Env, Error, NewBinary, NifResult};

/// LtHash lane count and state width, mirroring
/// `Exosphere.ATProto.Spaces.Lthash`. The state is `LANES` little-endian
/// `u16`s; elements expand to exactly this many bytes.
const LANES: usize = 1024;
const STATE_BYTES: usize = LANES * 2;

/// Squeeze `out_len` bytes of BLAKE3 XOF output for `input`.
fn xof(input: &[u8], out: &mut [u8]) {
    let mut hasher = blake3::Hasher::new();
    hasher.update(input);
    hasher.finalize_xof().fill(out);
}

fn new_binary<'a>(env: Env<'a>, len: usize) -> NewBinary<'a> {
    NewBinary::new(env, len)
}

fn hash_xof_impl<'a>(env: Env<'a>, input: Binary, out_len: usize) -> NifResult<Binary<'a>> {
    if out_len == 0 {
        return Err(Error::BadArg);
    }

    let mut out = new_binary(env, out_len);
    xof(input.as_slice(), out.as_mut_slice());
    Ok(out.into())
}

/// XOF for inputs small enough to stay well inside a normal NIF's time budget.
/// `Exosphere.ATProto.Spaces.Blake3` routes larger calls to the dirty variant.
#[rustler::nif]
fn hash_xof<'a>(env: Env<'a>, input: Binary, out_len: usize) -> NifResult<Binary<'a>> {
    hash_xof_impl(env, input, out_len)
}

/// XOF on a dirty CPU scheduler, for inputs or outputs large enough that the
/// hash could otherwise hold a normal scheduler past its ~1ms budget.
#[rustler::nif(schedule = "DirtyCpu")]
fn hash_xof_dirty<'a>(env: Env<'a>, input: Binary, out_len: usize) -> NifResult<Binary<'a>> {
    hash_xof_impl(env, input, out_len)
}

/// Fold one element's expansion into the lanes: wrapping add when `add` is
/// true, wrapping subtract when false. Both are mod 2^16, so removal is the
/// exact inverse of addition and the state depends only on the element *set*.
fn fold_element(state: &mut [u8], element: &[u8], add: bool) {
    let mut expanded = [0u8; STATE_BYTES];
    xof(element, &mut expanded);

    for lane in 0..LANES {
        let i = lane * 2;
        let s = u16::from_le_bytes([state[i], state[i + 1]]);
        let e = u16::from_le_bytes([expanded[i], expanded[i + 1]]);
        let folded = if add {
            s.wrapping_add(e)
        } else {
            s.wrapping_sub(e)
        };
        state[i..i + 2].copy_from_slice(&folded.to_le_bytes());
    }
}

fn check_state(state: &Binary) -> NifResult<()> {
    if state.len() == STATE_BYTES {
        Ok(())
    } else {
        Err(Error::BadArg)
    }
}

/// Fold a single element into an LtHash state.
#[rustler::nif]
fn lthash_fold<'a>(
    env: Env<'a>,
    state: Binary,
    element: Binary,
    add: bool,
) -> NifResult<Binary<'a>> {
    check_state(&state)?;

    let mut out = new_binary(env, STATE_BYTES);
    let slice = out.as_mut_slice();
    slice.copy_from_slice(state.as_slice());
    fold_element(slice, element.as_slice(), add);

    Ok(out.into())
}

/// Fold many elements into an LtHash state in one call — the bulk path for
/// verifying a full repo CAR or replaying an oplog. Dirty-scheduled: the
/// element count is caller-controlled and a large repo would otherwise hold a
/// normal scheduler far past its budget.
#[rustler::nif(schedule = "DirtyCpu")]
fn lthash_fold_many<'a>(
    env: Env<'a>,
    state: Binary,
    elements: Vec<Binary>,
    add: bool,
) -> NifResult<Binary<'a>> {
    check_state(&state)?;

    let mut out = new_binary(env, STATE_BYTES);
    let slice = out.as_mut_slice();
    slice.copy_from_slice(state.as_slice());

    for element in elements {
        fold_element(slice, element.as_slice(), add);
    }

    Ok(out.into())
}

rustler::init!("Elixir.Exosphere.ATProto.Spaces.Blake3.Native");
