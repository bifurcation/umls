use crate::common::*;
use crate::crypto::*;
use crate::io::Write;
use crate::protocol::{self, *};
use crate::stack::*;
use crate::syntax::Serialize;
use crate::{stack_ptr, tick};

pub fn confirmed(
    interim_transcript_hash: HashOutputView,
    content: &FramedContent,
    signature: &Signature,
) -> Result<HashOutput> {
    tick!();
    let mut h = Hash::new();

    h.write(interim_transcript_hash.as_ref())?;
    protocol::consts::SUPPORTED_WIRE_FORMAT.serialize(&mut h)?;
    content.serialize(&mut h)?;
    signature.serialize(&mut h)?;

    Ok(h.finalize())
}

pub fn interim(
    confirmed_transcript_hash: &HashOutput,
    confirmation_tag: &HashOutput,
) -> Result<HashOutput> {
    tick!();
    let mut h = Hash::new();

    h.write(confirmed_transcript_hash.as_ref())?;
    confirmation_tag.serialize(&mut h)?;

    Ok(h.finalize())
}
