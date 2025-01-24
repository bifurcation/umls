use umls_core::{
    common::*,
    crypto::*,
    io::*,
    protocol::{self, *},
    syntax::*,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct InterimTranscriptHash<C: Crypto>(HashOutput<C>);

pub fn confirmed<C: CryptoSizes>(
    interim_transcript_hash: &InterimTranscriptHash<C>,
    content: &FramedContent<C>,
    signature: &Signature<C>,
) -> Result<ConfirmedTranscriptHash<C>> {
    let mut h = C::Hash::default();

    h.write(interim_transcript_hash.0.as_ref())?;
    protocol::consts::SUPPORTED_WIRE_FORMAT.serialize(&mut h)?;
    content.serialize(&mut h)?;
    signature.serialize(&mut h)?;

    Ok(ConfirmedTranscriptHash(h.finalize()))
}

pub fn interim<C: Crypto>(
    confirmed_transcript_hash: &ConfirmedTranscriptHash<C>,
    confirmation_tag: &ConfirmationTag<C>,
) -> Result<InterimTranscriptHash<C>> {
    let mut h = C::Hash::default();

    h.write(confirmed_transcript_hash.0.as_ref())?;
    confirmation_tag.serialize(&mut h)?;

    Ok(InterimTranscriptHash(h.finalize()))
}
