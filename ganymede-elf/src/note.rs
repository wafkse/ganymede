//! GNU build identity extraction from loaded ELF images.
//!
//! This module interprets only ELF headers, program headers, and `PT_NOTE` payloads. Process access
//! remains in Ganymede process and loader protocols remain outside this boundary.

extern crate alloc;

use alloc::boxed::Box;

use ganymede_process::process::{Process, ReadError};

use crate::{
    binding,
    class::{Class, ProgramHeader},
    image::LoadBias,
    loaded::{LoadedImage, LoadedImageError},
};

/// ELF note name used by GNU properties.
const GNU_NAME: &[u8] = b"GNU";

/// GNU build identifier note kind.
const GNU_BUILD_ID: u32 = 3;

/// Exact nonempty GNU build identifier descriptor.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
// NOTE(invariant): Construction accepts only a nonempty descriptor and no mutation is exposed.
pub struct GnuBuildId(Box<[u8]>);

impl GnuBuildId {
    /// Validate and retain one exact descriptor supplied by a trusted catalog loader.
    ///
    /// # Errors
    ///
    /// This rejects an empty descriptor.
    #[inline]
    pub fn new(descriptor: impl Into<Box<[u8]>>) -> Result<Self, BuildIdError> {
        let descriptor = descriptor.into();

        if descriptor.is_empty() {
            return Err(BuildIdError::EmptyBuildId);
        }

        Ok(Self(descriptor))
    }

    /// Read the unique GNU build identifier from one loaded image.
    ///
    /// The load bias and selected class determine the complete ELF representation. The operation
    /// invokes no target code and reads only bounded process memory.
    ///
    /// # Errors
    ///
    /// This preserves process access failures and rejects malformed ELF identity, invalid table
    /// geometry, malformed note records, missing identifiers, and ambiguity.
    #[inline]
    pub fn read<ClassType>(
        process: &Process,
        load_bias: LoadBias<ClassType>,
    ) -> Result<Self, BuildIdError>
    where
        ClassType: Class,
    {
        let image = LoadedImage::<ClassType>::read(process, load_bias)?;

        Self::extract(&image)
    }

    /// Inspect every note segment and require one exact GNU build identifier.
    fn extract<ClassType>(image: &LoadedImage<'_, ClassType>) -> Result<Self, BuildIdError>
    where
        ClassType: Class,
    {
        let process = image.process();
        let load_bias = image.load_bias();
        let mut build_id = None;

        for program_header in image.program_headers() {
            if program_header.kind() != binding::PT_NOTE as u32 {
                continue;
            }

            let size = program_header
                .file()
                .try_into()
                .map_err(|_| BuildIdError::AddressOverflow)?;

            if size == 0 {
                continue;
            }

            let address = load_bias
                .address(program_header.address())
                .ok_or(BuildIdError::AddressOverflow)?;
            let bytes = process.read_bytes(address, size)?;
            let segment = Notes::new(&bytes);

            for descriptor in segment {
                let descriptor = descriptor?;

                if build_id.replace(descriptor).is_some() {
                    return Err(BuildIdError::Ambiguous);
                }
            }
        }

        let bytes = build_id.ok_or(BuildIdError::Missing)?;

        Self::new(bytes)
    }

    /// Borrow the exact descriptor bytes.
    #[inline]
    #[must_use]
    pub const fn bytes(&self) -> &[u8] {
        let Self(bytes) = self;

        bytes
    }
}

/// Failure while extracting one GNU build identifier.
#[derive(Debug, thiserror::Error)]
pub enum BuildIdError {
    /// Loaded-image validation failed before note interpretation.
    #[error(transparent)]
    Image(#[from] LoadedImageError),

    /// Owned note bytes could not be acquired.
    #[error(transparent)]
    Read(#[from] ReadError),

    /// Address arithmetic overflowed in the selected ELF width.
    #[error("loaded image address arithmetic overflowed")]
    AddressOverflow,

    /// A note record ended before its declared fields were complete.
    #[error("ELF note record is truncated or has invalid padding")]
    MalformedNote,

    /// A GNU build identifier descriptor was empty.
    #[error("GNU build identifier descriptor is empty")]
    EmptyBuildId,

    /// No GNU build identifier note was present.
    #[error("loaded image has no GNU build identifier")]
    Missing,

    /// More than one GNU build identifier was present.
    #[error("loaded image has multiple GNU build identifiers")]
    Ambiguous,
}

/// Iterator over GNU build identifiers in one complete note segment.
// NOTE(invariant): `offset` begins at zero and advances only to checked padded record boundaries within `bytes`.
struct Notes<'note> {
    /// Complete acquired note segment.
    bytes: &'note [u8],

    /// Next record boundary within `bytes`.
    offset: usize,
}

impl<'note> Notes<'note> {
    /// Bind one complete byte segment to the parser.
    #[inline]
    const fn new(bytes: &'note [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    /// Round one declared field extent up to ELF note alignment.
    #[inline]
    const fn aligned(size: usize) -> Option<usize> {
        match size.checked_add(3) {
            Some(value) => Some(value & !3),
            None => None,
        }
    }

    /// Read one little-endian note word and advance the cursor.
    fn word(&mut self) -> Result<u32, BuildIdError> {
        let Self { bytes, offset, .. } = self;
        let end = offset.checked_add(4).ok_or(BuildIdError::MalformedNote)?;
        let value = bytes
            .get(*offset..end)
            .and_then(|value| <[u8; 4]>::try_from(value).ok())
            .ok_or(BuildIdError::MalformedNote)?;

        *offset = end;

        Ok(u32::from_le_bytes(value))
    }

    /// Read one declared byte field and advance across its padded extent.
    fn field(&mut self, size: usize) -> Result<&'note [u8], BuildIdError> {
        let Self { bytes, offset, .. } = self;
        let padded = Self::aligned(size).ok_or(BuildIdError::MalformedNote)?;
        let value_end = offset
            .checked_add(size)
            .ok_or(BuildIdError::MalformedNote)?;
        let padded_end = offset
            .checked_add(padded)
            .ok_or(BuildIdError::MalformedNote)?;
        let value = bytes
            .get(*offset..value_end)
            .ok_or(BuildIdError::MalformedNote)?;

        if bytes.get(value_end..padded_end).is_none() {
            return Err(BuildIdError::MalformedNote);
        }

        *offset = padded_end;

        Ok(value)
    }
}

impl Iterator for Notes<'_> {
    type Item = Result<Box<[u8]>, BuildIdError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let Self { bytes, offset, .. } = self;
            let remaining = bytes.get(*offset..)?;

            if remaining.is_empty() || remaining.iter().all(|byte| *byte == 0) {
                return None;
            }

            let result = (|| {
                let name_size =
                    usize::try_from(self.word()?).map_err(|_| BuildIdError::MalformedNote)?;
                let descriptor_size =
                    usize::try_from(self.word()?).map_err(|_| BuildIdError::MalformedNote)?;
                let note_type = self.word()?;
                let name = self.field(name_size)?;
                let descriptor = self.field(descriptor_size)?;
                let name = name.strip_suffix(&[0]).unwrap_or(name);

                if note_type != GNU_BUILD_ID || name != GNU_NAME {
                    return Ok(None);
                }

                if descriptor.is_empty() {
                    return Err(BuildIdError::EmptyBuildId);
                }

                Ok(Some(Box::<[u8]>::from(descriptor)))
            })();

            match result {
                Ok(Some(build_id)) => return Some(Ok(build_id)),
                Ok(None) => {}
                Err(error) => return Some(Err(error)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Pure parser coverage for ELF note records.

    use super::*;

    #[test]
    fn note_parser_finds_one_gnu_build_identifier() {
        let bytes = [
            4, 0, 0, 0, 4, 0, 0, 0, 3, 0, 0, 0, b'G', b'N', b'U', 0, 1, 2, 3, 4,
        ];
        let mut notes = Notes::new(&bytes);
        let build_id = notes
            .next()
            .expect("the fixture contains one note")
            .expect("the fixture note is valid");

        assert_eq!(build_id.as_ref(), &[1, 2, 3, 4]);
        assert!(notes.next().is_none());
    }

    #[test]
    fn note_parser_rejects_truncated_padding() {
        let bytes = [
            4, 0, 0, 0, 3, 0, 0, 0, 3, 0, 0, 0, b'G', b'N', b'U', 0, 1, 2, 3,
        ];
        let mut notes = Notes::new(&bytes);

        assert!(matches!(
            notes.next(),
            Some(Err(BuildIdError::MalformedNote))
        ));
    }
}
