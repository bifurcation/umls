use umls_core::{
    common::Result,
    crypto::{Crypto, CryptoSizes, Hash, HashOutput, Signature},
    io::{BorrowRead, Read, Write},
    protocol::{self, ConfirmationTag, ConfirmedTranscriptHash, FramedContent},
    stack,
    syntax::{Deserialize, Parse, Serialize, View},
};

#[derive(Debug, Serialize, Deserialize, View)]
pub struct InterimTranscriptHash<C>(HashOutput<C>)
where
    C: Crypto;

pub fn confirmed<C>(
    interim_transcript_hash: &InterimTranscriptHash<C>,
    content: &FramedContent<C>,
    signature: &Signature<C>,
) -> Result<ConfirmedTranscriptHash<C>>
where
    C: CryptoSizes,
{
    stack::update();
    let mut h = C::Hash::default();

    h.write(interim_transcript_hash.0.as_ref())?;
    protocol::consts::SUPPORTED_WIRE_FORMAT.serialize(&mut h)?;
    content.serialize(&mut h)?;
    signature.serialize(&mut h)?;

    Ok(ConfirmedTranscriptHash(h.finalize()))
}

pub fn interim<C>(
    confirmed_transcript_hash: &ConfirmedTranscriptHash<C>,
    confirmation_tag: &ConfirmationTag<C>,
) -> Result<InterimTranscriptHash<C>>
where
    C: Crypto,
{
    stack::update();
    let mut h = C::Hash::default();

    h.write(confirmed_transcript_hash.0.as_ref())?;
    confirmation_tag.serialize(&mut h)?;

    Ok(InterimTranscriptHash(h.finalize()))
}
