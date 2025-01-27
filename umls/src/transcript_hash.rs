use umls_core::{
    common::Result,
    crypto::{Crypto, CryptoSizes, Hash, HashOutput, Hmac, Signature},
    io::{Read, Write},
    protocol::{self, ConfirmationTag, ConfirmedTranscriptHash, FramedContent},
    stack,
    syntax::{Deserialize, Serialize},
};

#[derive(Debug, Serialize, Deserialize)]
pub struct InterimTranscriptHash<C: Crypto>(HashOutput<C>);

pub fn confirmed<C: CryptoSizes>(
    interim_transcript_hash: &InterimTranscriptHash<C>,
    content: &FramedContent<C>,
    signature: &Signature<C>,
) -> Result<ConfirmedTranscriptHash<C>> {
    stack::update();
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
    stack::update();
    let mut h = C::Hash::default();

    h.write(confirmed_transcript_hash.0.as_ref())?;
    confirmation_tag.serialize(&mut h)?;

    Ok(InterimTranscriptHash(h.finalize()))
}
