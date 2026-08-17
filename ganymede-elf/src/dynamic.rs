//! Discovery and lookup of process-resident ELF dynamic symbols.
//!
//! One class-generic implementation handles ELF32 and ELF64. Dynamic values and symbol records keep
//! their selected ELF width while process addresses are produced only through checked load-bias
//! translation. System V and GNU hash traversal remain shared because their indices and chain words
//! are class-independent.

extern crate alloc;

use core::{mem, num::NonZeroUsize};

use catalejo::{address::ViAddr, prelude::Lift};
use ganymede_process::process::{AccessError, Process, ReadError};
use num_traits::One;

use crate::{
    binding,
    class::{Class, Elf32, Elf64, ElfClass},
    image::LoadBias,
    lift::{Dynamic, ElfError},
    loaded::{LoadedImage, LoadedImageError},
    symbol::{DynamicSymbol, Export, Symbol, SymbolError},
};

/// Semantic dynamic-table terminator tag.
const DT_NULL: i64 = binding::DT_NULL as i64;

/// Semantic dynamic string-table pointer tag.
const DT_STRTAB: i64 = binding::DT_STRTAB as i64;

/// Semantic dynamic string-table size tag.
const DT_STRSZ: i64 = binding::DT_STRSZ as i64;

/// Semantic dynamic symbol-table pointer tag.
const DT_SYMTAB: i64 = binding::DT_SYMTAB as i64;

/// Semantic dynamic symbol-entry stride tag.
const DT_SYMENT: i64 = binding::DT_SYMENT as i64;

/// Semantic System V symbol-hash pointer tag.
const DT_HASH: i64 = binding::DT_HASH as i64;

/// Semantic GNU symbol-hash pointer tag.
const DT_GNU_HASH: i64 = binding::DT_GNU_HASH as i64;

/// Byte width of one hash bucket or chain word.
const HASH_WORD_BYTES: u64 = mem::size_of::<u32>() as u64;

/// System V hash-table words before the bucket array.
///
/// The first words are `nbucket` and `nchain`. The bucket array follows immediately and the chain
/// array follows all buckets.
///
/// <https://refspecs.linuxfoundation.org/elf/gabi4%2B/ch5.dynamic.html>
const SYSV_HASH_HEADER_WORDS: u64 = 2;

/// Byte offset of the System V chain-count word.
const SYSV_HASH_CHAIN_COUNT_OFFSET: u64 = HASH_WORD_BYTES;

/// Byte offset where the System V bucket array begins.
const SYSV_HASH_BUCKETS_OFFSET: u64 = SYSV_HASH_HEADER_WORDS * HASH_WORD_BYTES;

/// Left shift applied for each byte by the System V ELF hash function.
const SYSV_HASH_BYTE_SHIFT: u32 = 4;

/// High hash bits folded back into the System V ELF hash accumulator.
const SYSV_HASH_HIGH_MASK: u32 = 0xf000_0000;

/// Right shift used when folding the System V high hash bits.
const SYSV_HASH_FOLD_SHIFT: u32 = 24;

/// GNU hash-table words before the bloom filter.
///
/// The words are bucket count, first chain symbol index, bloom word count, and bloom shift. The
/// class-sized bloom filter follows these words, then the 32-bit bucket and chain arrays.
///
/// <https://sourceware.org/pipermail/binutils/2006-October/049450.html>
const GNU_HASH_HEADER_WORDS: u64 = 4;

/// Byte offset of the GNU first-chain-symbol word.
const GNU_HASH_SYMBOL_OFFSET: u64 = HASH_WORD_BYTES;

/// Byte offset of the GNU bloom-word-count field.
const GNU_HASH_BLOOM_COUNT_OFFSET: u64 = HASH_WORD_BYTES * 2;

/// Byte offset of the GNU second-bloom-bit shift field.
const GNU_HASH_BLOOM_SHIFT_OFFSET: u64 = HASH_WORD_BYTES * 3;

/// Byte offset where the GNU bloom filter begins.
const GNU_HASH_BLOOM_OFFSET: u64 = GNU_HASH_HEADER_WORDS * HASH_WORD_BYTES;

/// Low chain-word bit that marks the final symbol in one GNU bucket chain.
const GNU_HASH_CHAIN_TERMINATOR: u32 = 1;

/// Chain-word bits that participate in GNU hash comparison.
const GNU_HASH_CHAIN_VALUE_MASK: u32 = !GNU_HASH_CHAIN_TERMINATOR;

/// Initial accumulator value of the GNU dynamic symbol hash function.
const GNU_HASH_INITIAL: u32 = 5381;

/// Multiplier applied for each byte by the GNU dynamic symbol hash function.
const GNU_HASH_MULTIPLIER: u32 = 33;

/// Dynamic-table values required to construct one symbol lookup view.
#[derive(Debug, Clone, Copy)]
struct Metadata<ClassType>
where
    ClassType: Class,
{
    /// Virtual address of the dynamic string table.
    string_table: Option<ClassType::Word>,
    /// Declared byte size of the dynamic string table.
    string_size: Option<ClassType::Word>,
    /// Virtual address of the dynamic symbol table.
    symbol_table: Option<ClassType::Word>,
    /// Declared byte stride of one dynamic symbol record.
    symbol_stride: Option<ClassType::Word>,
    /// Virtual address of the System V hash table when present.
    sysv_hash: Option<ClassType::Word>,
    /// Virtual address of the GNU hash table when present.
    gnu_hash: Option<ClassType::Word>,
}

/// Proven dynamic hash-table mechanism used to locate symbols by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HashTable {
    /// System V ELF hash table.
    Sysv {
        /// Runtime table address.
        address: ViAddr,

        /// Number of buckets.
        buckets: NonZeroUsize,

        /// Number of symbol-chain entries.
        symbols: NonZeroUsize,
    },

    /// GNU hash table.
    Gnu {
        /// Runtime table address.
        address: ViAddr,

        /// Number of buckets.
        buckets: NonZeroUsize,

        /// First symbol index represented by the chain table.
        symbol_offset: u32,

        /// Number of class-sized bloom-filter words.
        bloom_words: NonZeroUsize,

        /// Bloom-filter second-bit shift.
        bloom_shift: u32,

        /// Number of complete chain words contained by the validated load segment.
        chain_words: NonZeroUsize,
    },
}

/// Validated start state for one nonempty GNU hash bucket chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// NOTE(invariant): `symbol` is at or beyond the GNU table's first chain symbol and `chains` is the checked byte offset of the chain array from the hash-table base.
struct GnuBucket {
    /// First dynamic symbol index selected by the bucket.
    symbol: u32,

    /// Checked byte offset of the GNU chain array.
    chains: u64,
}

/// Process-resident dynamic-symbol lookup context for one selected ELF class.
#[derive(Debug, Clone, PartialEq, Eq)]
// NOTE(invariant): All retained table addresses come from one terminated dynamic table inside one validated loaded image, the symbol stride matches the selected raw symbol record, and string and symbol extents remain within validated `PT_LOAD` memory geometry.
pub struct DynamicSymbols<ClassType>
where
    ClassType: Class,
{
    /// Load bias used for symbol values and dynamic pointers.
    load_bias: LoadBias<ClassType>,

    /// Runtime dynamic symbol table address.
    symbol_table: ViAddr,

    /// Number of complete symbol records available before the containing load segment ends.
    symbol_capacity: usize,

    /// Runtime dynamic string table address.
    string_table: ViAddr,

    /// Exact `DT_STRSZ` extent of the dynamic string table.
    string_size: usize,

    /// Hash mechanism that bounds and indexes symbol lookup.
    hash_table: HashTable,
}

impl<ClassType> DynamicSymbols<ClassType>
where
    ClassType: Class,
    Dynamic<ClassType>: Lift<Value = ClassType::Dynamic, Context = (), Error = ElfError>,
    Symbol<ClassType>: Lift<Value = ClassType::Symbol, Context = (), Error = ElfError>,
{
    /// Discover dynamic symbols using one validated loaded image.
    ///
    /// Dynamic pointers remain class-sized until translated through the image load bias. The exact
    /// `PT_DYNAMIC` extent bounds metadata scanning, `DT_STRSZ` bounds symbol names, and validated
    /// `PT_LOAD` extents bound symbol and hash table access.
    ///
    /// # Errors
    ///
    /// This returns an error for malformed or incomplete dynamic metadata, unsupported hash layout,
    /// target or process address overflow, foreign access failure, or protected read faults.
    #[inline]
    pub fn read_loaded(
        target_image: &LoadedImage<'_, ClassType>,
        target_dynamic: ViAddr,
    ) -> Result<Self, DynamicSymbolsError> {
        let dynamic_range = target_image
            .dynamic_range()
            .ok_or(DynamicSymbolsError::InvalidDynamicTable)?;

        if dynamic_range.start_address != target_dynamic {
            return Err(DynamicSymbolsError::DynamicTableOutsideImage(
                target_dynamic,
            ));
        }

        let ViAddr(dynamic_start) = dynamic_range.start_address;
        let ViAddr(dynamic_end) = dynamic_range.end_address;
        let dynamic_bytes = dynamic_end
            .checked_sub(dynamic_start)
            .and_then(|target_bytes| usize::try_from(target_bytes).ok())
            .ok_or(DynamicSymbolsError::InvalidDynamicTable)?;
        let stride = mem::size_of::<ClassType::Dynamic>();
        let complete = stride != 0 && dynamic_bytes != 0 && dynamic_bytes % stride == 0;

        if !complete {
            return Err(DynamicSymbolsError::InvalidDynamicTable);
        }

        Self::read_with(target_image, target_dynamic, dynamic_bytes / stride)
    }

    /// Read one complete dynamic segment and retain structurally bounded lookup metadata.
    fn read_with(
        target_image: &LoadedImage<'_, ClassType>,
        target_dynamic: ViAddr,
        target_dynamic_entries: usize,
    ) -> Result<Self, DynamicSymbolsError> {
        let target_process = target_image.process();
        let target_load_bias = target_image.load_bias();
        let metadata = Self::metadata(target_process, target_dynamic, target_dynamic_entries)?;
        let string_table_virtual = metadata
            .string_table
            .ok_or(DynamicSymbolsError::Missing(DynamicField::StringTable))?;
        let string_table_size = metadata
            .string_size
            .ok_or(DynamicSymbolsError::Missing(DynamicField::StringSize))?;
        let symbol_table_virtual = metadata
            .symbol_table
            .ok_or(DynamicSymbolsError::Missing(DynamicField::SymbolTable))?;
        let symbol_stride = metadata
            .symbol_stride
            .ok_or(DynamicSymbolsError::Missing(DynamicField::SymbolStride))?;
        Self::symbol_stride(symbol_stride)?;

        let string_size: usize = string_table_size
            .try_into()
            .map_err(|_| DynamicSymbolsError::StringTableOutsideImage)?;
        let string_table = Self::pointer(target_image, string_table_virtual)?;
        let string_available = target_image
            .load_bytes(string_table)
            .ok_or(DynamicSymbolsError::StringTableOutsideImage)?;

        if string_size > string_available {
            return Err(DynamicSymbolsError::StringTableOutsideImage);
        }

        let symbol_table = Self::pointer(target_image, symbol_table_virtual)?;
        let symbol_bytes = target_image
            .load_bytes(symbol_table)
            .ok_or(DynamicSymbolsError::SymbolTableOutsideImage)?;
        let symbol_stride = mem::size_of::<ClassType::Symbol>();
        let symbol_capacity = symbol_bytes / symbol_stride;

        if symbol_capacity == 0 {
            return Err(DynamicSymbolsError::SymbolTableOutsideImage);
        }

        let hash_table = Self::hash(
            target_process,
            target_image,
            metadata.sysv_hash,
            metadata.gnu_hash,
            symbol_capacity,
        )?;

        Ok(Self {
            load_bias: target_load_bias,
            symbol_table,
            symbol_capacity,
            string_table,
            string_size,
            hash_table,
        })
    }

    /// Collect the unique dynamic values required for symbol lookup.
    fn metadata(
        target_process: &Process,
        target_dynamic: ViAddr,
        target_dynamic_entries: usize,
    ) -> Result<Metadata<ClassType>, DynamicSymbolsError> {
        let stride = u64::try_from(mem::size_of::<ClassType::Dynamic>())
            .map_err(|_| DynamicSymbolsError::InvalidClassLayout(ClassType::CLASS))?;
        let mut metadata = Metadata {
            string_table: None,
            string_size: None,
            symbol_table: None,
            symbol_stride: None,
            sysv_hash: None,
            gnu_hash: None,
        };

        for index in 0..target_dynamic_entries {
            let index = u64::try_from(index).map_err(|_| DynamicSymbolsError::AddressOverflow)?;
            let offset = index
                .checked_mul(stride)
                .ok_or(DynamicSymbolsError::AddressOverflow)?;
            let address = Self::add(target_dynamic, offset)?;
            let foreign = Process::open::<ClassType::Dynamic>(target_process, address)
                .map_err(DynamicSymbolsError::access)?;
            let entry = foreign
                .lift::<Dynamic<ClassType>>()
                .map_err(|source| DynamicSymbolsError::Lift { address, source })?;
            let tag = Dynamic::tag(&entry);
            let value = Dynamic::value(&entry);

            match tag {
                DT_NULL => return Ok(metadata),
                DT_STRTAB => {
                    Self::unique(&mut metadata.string_table, value, DynamicField::StringTable)?;
                }
                DT_STRSZ => {
                    Self::unique(&mut metadata.string_size, value, DynamicField::StringSize)?;
                }
                DT_SYMTAB => {
                    Self::unique(&mut metadata.symbol_table, value, DynamicField::SymbolTable)?;
                }
                DT_SYMENT => {
                    Self::unique(
                        &mut metadata.symbol_stride,
                        value,
                        DynamicField::SymbolStride,
                    )?;
                }
                DT_HASH => Self::unique(&mut metadata.sysv_hash, value, DynamicField::SysvHash)?,
                DT_GNU_HASH => Self::unique(&mut metadata.gnu_hash, value, DynamicField::GnuHash)?,
                _ => {}
            }
        }

        Err(DynamicSymbolsError::MissingTerminator)
    }

    /// Require the generated symbol representation to match `DT_SYMENT` exactly.
    fn symbol_stride(target_stride: ClassType::Word) -> Result<(), DynamicSymbolsError> {
        let host_stride = u64::try_from(mem::size_of::<ClassType::Symbol>())
            .map_err(|_| DynamicSymbolsError::InvalidClassLayout(ClassType::CLASS))?;
        let expected_stride = ClassType::Word::try_from(host_stride)
            .ok()
            .ok_or(DynamicSymbolsError::InvalidClassLayout(ClassType::CLASS))?;

        if target_stride == expected_stride {
            Ok(())
        } else {
            Err(DynamicSymbolsError::InvalidSymbolStride(
                target_stride.into(),
            ))
        }
    }

    /// Find one dynamic symbol by exact byte name.
    ///
    /// # Errors
    ///
    /// This returns an error when hash traversal, symbol acquisition, string-table indexing, or
    /// foreign access violates the validated lookup bounds.
    #[inline]
    pub fn find(
        &self,
        target_process: &Process,
        target_name: &[u8],
    ) -> Result<Option<DynamicSymbol<ClassType>>, DynamicSymbolsError> {
        let Self { hash_table, .. } = self;

        match hash_table {
            HashTable::Sysv { .. } => self.sysv(target_process, target_name),
            HashTable::Gnu { .. } => self.gnu(target_process, target_name),
        }
    }

    /// Resolve one externally visible dynamic symbol to a fixed process address.
    ///
    /// # Errors
    ///
    /// This returns the same failures as [`Self::find`] plus class-width symbol-address translation
    /// failures.
    #[inline]
    pub fn export(
        &self,
        target_process: &Process,
        target_name: &[u8],
    ) -> Result<Option<Export<ClassType>>, DynamicSymbolsError> {
        let symbol = self.find(target_process, target_name)?;
        let Self { load_bias, .. } = self;

        symbol.map_or(Ok(None), |symbol| {
            Export::new(symbol, *load_bias).map_err(Into::into)
        })
    }

    /// Borrow the image load bias used for symbol resolution.
    #[inline]
    #[must_use]
    pub const fn load_bias(&self) -> &LoadBias<ClassType> {
        let Self { load_bias, .. } = self;

        load_bias
    }

    /// Resolve one exact name through a validated System V hash table.
    fn sysv(
        &self,
        target_process: &Process,
        target_name: &[u8],
    ) -> Result<Option<DynamicSymbol<ClassType>>, DynamicSymbolsError> {
        let Self { hash_table, .. } = self;
        let (address, buckets, symbols) = match hash_table {
            HashTable::Sysv {
                address,
                buckets,
                symbols,
            } => (*address, *buckets, *symbols),
            HashTable::Gnu { .. } => return Err(DynamicSymbolsError::InvalidHash),
        };
        let hash = Self::sysv_hash(target_name);
        let bucket_index =
            usize::try_from(hash).map_err(|_| DynamicSymbolsError::InvalidHash)? % buckets.get();
        let bucket_offset = SYSV_HASH_BUCKETS_OFFSET
            .checked_add(
                u64::try_from(bucket_index)
                    .map_err(|_| DynamicSymbolsError::AddressOverflow)?
                    .checked_mul(HASH_WORD_BYTES)
                    .ok_or(DynamicSymbolsError::AddressOverflow)?,
            )
            .ok_or(DynamicSymbolsError::AddressOverflow)?;
        let bucket_address = Self::add(address, bucket_offset)?;
        let mut symbol_index = Process::read::<u32>(target_process, bucket_address)?;

        for _target_step in 0..symbols.get() {
            if symbol_index == binding::STN_UNDEF as u32 {
                return Ok(None);
            }

            let in_range = usize::try_from(symbol_index)
                .is_ok_and(|target_index| target_index < symbols.get());

            if !in_range {
                return Err(DynamicSymbolsError::InvalidHash);
            }

            let symbol = self.symbol(target_process, symbol_index)?;

            if DynamicSymbol::name(&symbol) == target_name {
                return Ok(Some(symbol));
            }

            let chains_offset = SYSV_HASH_BUCKETS_OFFSET
                .checked_add(
                    u64::try_from(buckets.get())
                        .map_err(|_| DynamicSymbolsError::AddressOverflow)?
                        .checked_mul(HASH_WORD_BYTES)
                        .ok_or(DynamicSymbolsError::AddressOverflow)?,
                )
                .ok_or(DynamicSymbolsError::AddressOverflow)?;
            let chain_offset = u64::from(symbol_index)
                .checked_mul(HASH_WORD_BYTES)
                .and_then(|offset| chains_offset.checked_add(offset))
                .ok_or(DynamicSymbolsError::AddressOverflow)?;
            let chain_address = Self::add(address, chain_offset)?;

            symbol_index = Process::read::<u32>(target_process, chain_address)?;
        }

        Err(DynamicSymbolsError::InvalidHash)
    }

    /// Resolve one exact name through a validated GNU hash table.
    fn gnu(
        &self,
        target_process: &Process,
        target_name: &[u8],
    ) -> Result<Option<DynamicSymbol<ClassType>>, DynamicSymbolsError> {
        let Self { hash_table, .. } = self;
        let (address, buckets, symbol_offset, bloom_words, bloom_shift, chain_words) =
            match hash_table {
                HashTable::Gnu {
                    address,
                    buckets,
                    symbol_offset,
                    bloom_words,
                    bloom_shift,
                    chain_words,
                } => (
                    *address,
                    *buckets,
                    *symbol_offset,
                    *bloom_words,
                    *bloom_shift,
                    *chain_words,
                ),
                HashTable::Sysv { .. } => return Err(DynamicSymbolsError::InvalidHash),
            };
        let hash = Self::gnu_hash(target_name);
        let bloom_matches = Self::bloom(target_process, address, bloom_words, bloom_shift, hash)?;

        if !bloom_matches {
            return Ok(None);
        }

        Self::bucket(
            target_process,
            address,
            buckets,
            bloom_words,
            symbol_offset,
            hash,
        )?
        .map_or(Ok(None), |target_bucket| {
            self.chain(
                target_process,
                target_name,
                hash,
                symbol_offset,
                chain_words,
                target_bucket,
            )
        })
    }

    /// Test the class-sized GNU bloom filter before touching its bucket and chain arrays.
    fn bloom(
        target_process: &Process,
        target_address: ViAddr,
        target_words: NonZeroUsize,
        target_shift: u32,
        target_hash: u32,
    ) -> Result<bool, DynamicSymbolsError> {
        let word_bits = ClassType::BITS;
        let word_bytes = u64::try_from(mem::size_of::<ClassType::Word>())
            .map_err(|_| DynamicSymbolsError::InvalidClassLayout(ClassType::CLASS))?;
        let bloom_index = usize::try_from(target_hash / word_bits)
            .map_err(|_| DynamicSymbolsError::InvalidHash)?
            % target_words.get();
        let bloom_offset = GNU_HASH_BLOOM_OFFSET
            .checked_add(
                u64::try_from(bloom_index)
                    .map_err(|_| DynamicSymbolsError::AddressOverflow)?
                    .checked_mul(word_bytes)
                    .ok_or(DynamicSymbolsError::AddressOverflow)?,
            )
            .ok_or(DynamicSymbolsError::AddressOverflow)?;
        let bloom_address = Self::add(target_address, bloom_offset)?;
        let bloom = Process::read::<ClassType::Word>(target_process, bloom_address)?;
        let first_bit = usize::try_from(target_hash % word_bits)
            .map_err(|_| DynamicSymbolsError::InvalidClassLayout(ClassType::CLASS))?;
        let second_bit = usize::try_from((target_hash >> target_shift) % word_bits)
            .map_err(|_| DynamicSymbolsError::InvalidClassLayout(ClassType::CLASS))?;
        let one = ClassType::Word::one();
        let mask = (one << first_bit) | (one << second_bit);

        Ok(bloom & mask == mask)
    }

    /// Read and validate the GNU bucket selected by one name hash.
    fn bucket(
        target_process: &Process,
        target_address: ViAddr,
        target_buckets: NonZeroUsize,
        target_bloom_words: NonZeroUsize,
        target_symbol_offset: u32,
        target_hash: u32,
    ) -> Result<Option<GnuBucket>, DynamicSymbolsError> {
        let word_bytes = u64::try_from(mem::size_of::<ClassType::Word>())
            .map_err(|_| DynamicSymbolsError::InvalidClassLayout(ClassType::CLASS))?;
        let buckets_offset = GNU_HASH_BLOOM_OFFSET
            .checked_add(
                u64::try_from(target_bloom_words.get())
                    .map_err(|_| DynamicSymbolsError::AddressOverflow)?
                    .checked_mul(word_bytes)
                    .ok_or(DynamicSymbolsError::AddressOverflow)?,
            )
            .ok_or(DynamicSymbolsError::AddressOverflow)?;
        let bucket_index = usize::try_from(target_hash)
            .map_err(|_| DynamicSymbolsError::InvalidHash)?
            % target_buckets.get();
        let bucket_offset = u64::try_from(bucket_index)
            .map_err(|_| DynamicSymbolsError::AddressOverflow)?
            .checked_mul(HASH_WORD_BYTES)
            .and_then(|target_offset| buckets_offset.checked_add(target_offset))
            .ok_or(DynamicSymbolsError::AddressOverflow)?;
        let bucket_address = Self::add(target_address, bucket_offset)?;
        let symbol = Process::read::<u32>(target_process, bucket_address)?;

        if symbol == 0 {
            return Ok(None);
        }

        if symbol < target_symbol_offset {
            return Err(DynamicSymbolsError::InvalidHash);
        }

        let chains = buckets_offset
            .checked_add(
                u64::try_from(target_buckets.get())
                    .map_err(|_| DynamicSymbolsError::AddressOverflow)?
                    .checked_mul(HASH_WORD_BYTES)
                    .ok_or(DynamicSymbolsError::AddressOverflow)?,
            )
            .ok_or(DynamicSymbolsError::AddressOverflow)?;

        Ok(Some(GnuBucket { symbol, chains }))
    }

    /// Traverse one validated GNU hash chain until a name matches or mapped chain storage ends.
    fn chain(
        &self,
        target_process: &Process,
        target_name: &[u8],
        target_hash: u32,
        target_symbol_offset: u32,
        target_chain_words: NonZeroUsize,
        target_bucket: GnuBucket,
    ) -> Result<Option<DynamicSymbol<ClassType>>, DynamicSymbolsError> {
        let Self { hash_table, .. } = self;
        let address = match hash_table {
            HashTable::Gnu { address, .. } => *address,
            HashTable::Sysv { .. } => return Err(DynamicSymbolsError::InvalidHash),
        };
        let GnuBucket { mut symbol, chains } = target_bucket;

        loop {
            let relative_index = symbol
                .checked_sub(target_symbol_offset)
                .ok_or(DynamicSymbolsError::InvalidHash)?;
            let relative_index_host =
                usize::try_from(relative_index).map_err(|_| DynamicSymbolsError::InvalidHash)?;

            if relative_index_host >= target_chain_words.get() {
                return Err(DynamicSymbolsError::InvalidHash);
            }

            let chain_offset = u64::from(relative_index)
                .checked_mul(HASH_WORD_BYTES)
                .and_then(|target_offset| chains.checked_add(target_offset))
                .ok_or(DynamicSymbolsError::AddressOverflow)?;
            let chain_address = Self::add(address, chain_offset)?;
            let chain_hash = Process::read::<u32>(target_process, chain_address)?;
            let hash_matches =
                chain_hash & GNU_HASH_CHAIN_VALUE_MASK == target_hash & GNU_HASH_CHAIN_VALUE_MASK;
            let candidate = if hash_matches {
                Some(self.symbol(target_process, symbol)?)
            } else {
                None
            };
            let matched =
                candidate.filter(|target_symbol| DynamicSymbol::name(target_symbol) == target_name);
            let terminal = chain_hash & GNU_HASH_CHAIN_TERMINATOR != 0;

            if let Some(target_symbol) = matched {
                return Ok(Some(target_symbol));
            }

            if terminal {
                return Ok(None);
            }

            symbol = symbol
                .checked_add(1)
                .ok_or(DynamicSymbolsError::InvalidHash)?;
        }
    }

    /// Read one structurally bounded dynamic symbol and its validated string-table name.
    fn symbol(
        &self,
        target_process: &Process,
        target_index: u32,
    ) -> Result<DynamicSymbol<ClassType>, DynamicSymbolsError> {
        let Self {
            symbol_table,
            symbol_capacity,
            string_table,
            string_size,
            ..
        } = self;
        let index_valid =
            usize::try_from(target_index).is_ok_and(|target_index| target_index < *symbol_capacity);

        if !index_valid {
            return Err(DynamicSymbolsError::SymbolOutsideTable);
        }

        let symbol_stride = u64::try_from(mem::size_of::<ClassType::Symbol>())
            .map_err(|_| DynamicSymbolsError::InvalidClassLayout(ClassType::CLASS))?;
        let symbol_offset = u64::from(target_index)
            .checked_mul(symbol_stride)
            .ok_or(DynamicSymbolsError::AddressOverflow)?;
        let symbol_address = Self::add(*symbol_table, symbol_offset)?;
        let foreign = Process::open::<ClassType::Symbol>(target_process, symbol_address)
            .map_err(DynamicSymbolsError::access)?;
        let symbol =
            foreign
                .lift::<Symbol<ClassType>>()
                .map_err(|source| DynamicSymbolsError::Lift {
                    address: symbol_address,
                    source,
                })?;
        let name_offset = usize::try_from(Symbol::name_offset(&symbol))
            .map_err(|_| DynamicSymbolsError::InvalidNameOffset)?;
        let name_bytes = string_size
            .checked_sub(name_offset)
            .and_then(NonZeroUsize::new)
            .ok_or(DynamicSymbolsError::InvalidNameOffset)?;
        let name_offset =
            u64::try_from(name_offset).map_err(|_| DynamicSymbolsError::AddressOverflow)?;
        let name_address = Self::add(*string_table, name_offset)?;
        let name = Process::read_c_string_bytes(target_process, name_address, name_bytes).map_err(
            |target_error| match target_error {
                ReadError::MissingTerminator(..) => DynamicSymbolsError::MissingNameTerminator,
                target_error => DynamicSymbolsError::Read(target_error),
            },
        )?;

        Ok(DynamicSymbol::new(target_index, symbol, &name))
    }

    /// Validate the preferred available runtime symbol-hash structure.
    fn hash(
        target_process: &Process,
        target_image: &LoadedImage<'_, ClassType>,
        sysv_virtual: Option<ClassType::Word>,
        gnu_virtual: Option<ClassType::Word>,
        target_symbol_capacity: usize,
    ) -> Result<HashTable, DynamicSymbolsError> {
        match (gnu_virtual, sysv_virtual) {
            (Some(target_virtual), _) => Self::gnu_hash_table(
                target_process,
                target_image,
                target_virtual,
                target_symbol_capacity,
            ),
            (None, Some(target_virtual)) => Self::sysv_hash_table(
                target_process,
                target_image,
                target_virtual,
                target_symbol_capacity,
            ),
            (None, None) => Err(DynamicSymbolsError::MissingHash),
        }
    }

    /// Validate one GNU hash table against its containing load segment and symbol capacity.
    fn gnu_hash_table(
        target_process: &Process,
        target_image: &LoadedImage<'_, ClassType>,
        target_virtual: ClassType::Word,
        target_symbol_capacity: usize,
    ) -> Result<HashTable, DynamicSymbolsError> {
        let address = Self::pointer(target_image, target_virtual)?;
        let buckets = Process::read::<u32>(target_process, address)?;
        let symbol_offset =
            Process::read::<u32>(target_process, Self::add(address, GNU_HASH_SYMBOL_OFFSET)?)?;
        let bloom_words = Process::read::<u32>(
            target_process,
            Self::add(address, GNU_HASH_BLOOM_COUNT_OFFSET)?,
        )?;
        let bloom_shift = Process::read::<u32>(
            target_process,
            Self::add(address, GNU_HASH_BLOOM_SHIFT_OFFSET)?,
        )?;
        let buckets = usize::try_from(buckets)
            .ok()
            .and_then(NonZeroUsize::new)
            .ok_or(DynamicSymbolsError::InvalidHash)?;
        let bloom_words = usize::try_from(bloom_words)
            .ok()
            .and_then(NonZeroUsize::new)
            .ok_or(DynamicSymbolsError::InvalidHash)?;
        let symbol_offset_valid = usize::try_from(symbol_offset)
            .is_ok_and(|target_index| target_index < target_symbol_capacity);

        if bloom_shift >= u32::BITS || !symbol_offset_valid {
            return Err(DynamicSymbolsError::InvalidHash);
        }

        let word_bytes = u64::try_from(mem::size_of::<ClassType::Word>())
            .map_err(|_| DynamicSymbolsError::InvalidClassLayout(ClassType::CLASS))?;
        let bloom_bytes = u64::try_from(bloom_words.get())
            .map_err(|_| DynamicSymbolsError::AddressOverflow)?
            .checked_mul(word_bytes)
            .ok_or(DynamicSymbolsError::AddressOverflow)?;
        let bucket_bytes = u64::try_from(buckets.get())
            .map_err(|_| DynamicSymbolsError::AddressOverflow)?
            .checked_mul(HASH_WORD_BYTES)
            .ok_or(DynamicSymbolsError::AddressOverflow)?;
        let chains_offset = GNU_HASH_BLOOM_OFFSET
            .checked_add(bloom_bytes)
            .and_then(|target_offset| target_offset.checked_add(bucket_bytes))
            .ok_or(DynamicSymbolsError::AddressOverflow)?;
        let available = target_image
            .load_bytes(address)
            .ok_or(DynamicSymbolsError::InvalidHash)?;
        let chains_offset =
            usize::try_from(chains_offset).map_err(|_| DynamicSymbolsError::InvalidHash)?;
        let chain_bytes = available
            .checked_sub(chains_offset)
            .ok_or(DynamicSymbolsError::InvalidHash)?;
        let chain_words = NonZeroUsize::new(chain_bytes / mem::size_of::<u32>())
            .ok_or(DynamicSymbolsError::InvalidHash)?;

        Ok(HashTable::Gnu {
            address,
            buckets,
            symbol_offset,
            bloom_words,
            bloom_shift,
            chain_words,
        })
    }

    /// Validate one System V hash table against its containing load segment and symbol capacity.
    fn sysv_hash_table(
        target_process: &Process,
        target_image: &LoadedImage<'_, ClassType>,
        target_virtual: ClassType::Word,
        target_symbol_capacity: usize,
    ) -> Result<HashTable, DynamicSymbolsError> {
        let address = Self::pointer(target_image, target_virtual)?;
        let buckets = Process::read::<u32>(target_process, address)?;
        let symbols = Process::read::<u32>(
            target_process,
            Self::add(address, SYSV_HASH_CHAIN_COUNT_OFFSET)?,
        )?;
        let buckets = usize::try_from(buckets)
            .ok()
            .and_then(NonZeroUsize::new)
            .ok_or(DynamicSymbolsError::InvalidHash)?;
        let symbols = usize::try_from(symbols)
            .ok()
            .and_then(NonZeroUsize::new)
            .ok_or(DynamicSymbolsError::InvalidHash)?;

        if symbols.get() > target_symbol_capacity {
            return Err(DynamicSymbolsError::InvalidHash);
        }

        let words = SYSV_HASH_HEADER_WORDS
            .checked_add(
                u64::try_from(buckets.get()).map_err(|_| DynamicSymbolsError::AddressOverflow)?,
            )
            .and_then(|target_words| {
                u64::try_from(symbols.get())
                    .ok()
                    .and_then(|target_symbols| target_words.checked_add(target_symbols))
            })
            .ok_or(DynamicSymbolsError::AddressOverflow)?;
        let bytes = words
            .checked_mul(HASH_WORD_BYTES)
            .ok_or(DynamicSymbolsError::AddressOverflow)?;
        let available = target_image
            .load_bytes(address)
            .ok_or(DynamicSymbolsError::InvalidHash)?;
        let fits = usize::try_from(bytes).is_ok_and(|target_bytes| target_bytes <= available);

        if !fits {
            return Err(DynamicSymbolsError::InvalidHash);
        }

        Ok(HashTable::Sysv {
            address,
            buckets,
            symbols,
        })
    }

    /// Resolve one dynamic pointer against validated loaded-image geometry.
    fn pointer(
        target_image: &LoadedImage<'_, ClassType>,
        target_pointer: ClassType::Word,
    ) -> Result<ViAddr, DynamicSymbolsError> {
        target_image
            .resolve_dynamic_pointer(target_pointer)
            .ok_or_else(|| DynamicSymbolsError::PointerOutsideImage(target_pointer.into()))
    }

    /// Add a byte displacement to a process virtual address with overflow checking.
    #[inline]
    fn add(target_address: ViAddr, target_offset: u64) -> Result<ViAddr, DynamicSymbolsError> {
        let ViAddr(target_address) = target_address;

        target_address
            .checked_add(target_offset)
            .map(ViAddr::new)
            .ok_or(DynamicSymbolsError::AddressOverflow)
    }

    /// Record one uniquely interpreted dynamic value and reject disagreement.
    #[inline]
    fn unique<ValueType: Copy + PartialEq>(
        target_slot: &mut Option<ValueType>,
        target_value: ValueType,
        target_field: DynamicField,
    ) -> Result<(), DynamicSymbolsError> {
        let conflicts = target_slot.is_some_and(|target_existing| target_existing != target_value);

        if conflicts {
            return Err(DynamicSymbolsError::Duplicate(target_field));
        }

        *target_slot = Some(target_value);

        Ok(())
    }

    /// Compute the standard System V ELF symbol-name hash.
    #[inline]
    const fn sysv_hash(target_name: &[u8]) -> u32 {
        let mut hash = 0_u32;
        let mut index = 0_usize;

        while index < target_name.len() {
            hash = (hash << SYSV_HASH_BYTE_SHIFT).wrapping_add(target_name[index] as u32);
            let high = hash & SYSV_HASH_HIGH_MASK;
            hash ^= high >> SYSV_HASH_FOLD_SHIFT;
            hash &= !high;
            index += 1;
        }

        hash
    }

    /// Compute the GNU dynamic symbol-name hash.
    #[inline]
    const fn gnu_hash(target_name: &[u8]) -> u32 {
        let mut hash = GNU_HASH_INITIAL;
        let mut index = 0_usize;

        while index < target_name.len() {
            hash = hash
                .wrapping_mul(GNU_HASH_MULTIPLIER)
                .wrapping_add(target_name[index] as u32);
            index += 1;
        }

        hash
    }
}

/// Dynamic field required or uniquely interpreted for symbol lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DynamicField {
    /// Dynamic string-table pointer.
    #[error("dynamic string table")]
    StringTable,

    /// Dynamic string-table byte size.
    #[error("dynamic string table size")]
    StringSize,

    /// Dynamic symbol-table pointer.
    #[error("dynamic symbol table")]
    SymbolTable,

    /// Dynamic symbol entry stride.
    #[error("dynamic symbol stride")]
    SymbolStride,

    /// System V symbol hash table.
    #[error("System V symbol hash table")]
    SysvHash,

    /// GNU symbol hash table.
    #[error("GNU symbol hash table")]
    GnuHash,
}

/// Failure while discovering or resolving process-resident dynamic symbols.
#[derive(Debug, thiserror::Error)]
pub enum DynamicSymbolsError {
    /// Loaded-image acquisition failed before dynamic metadata interpretation.
    #[error(transparent)]
    Image(#[from] LoadedImageError),

    /// The complete dynamic segment had no `DT_NULL` terminator.
    #[error("ELF dynamic table has no terminator inside PT_DYNAMIC")]
    MissingTerminator,

    /// `PT_DYNAMIC` does not describe one unique nonempty table of complete entries.
    #[error("ELF dynamic segment has invalid table geometry")]
    InvalidDynamicTable,

    /// A required dynamic field was absent.
    #[error("missing {0}")]
    Missing(DynamicField),

    /// A uniquely interpreted dynamic field disagreed with an earlier occurrence.
    #[error("conflicting duplicate {0}")]
    Duplicate(DynamicField),

    /// Neither supported dynamic symbol hash table is present.
    #[error("ELF dynamic table has no supported symbol hash table")]
    MissingHash,

    /// The sealed class family selected a generated layout that cannot fit its own word width.
    #[error("generated layout does not fit {0:?}")]
    InvalidClassLayout(ElfClass),

    /// `DT_SYMENT` does not match the selected class symbol size.
    #[error("invalid ELF dynamic symbol stride {0}")]
    InvalidSymbolStride(u64),

    /// The declared dynamic string table exceeds validated load-segment memory.
    #[error("ELF dynamic string table extends outside the loaded image")]
    StringTableOutsideImage,

    /// The dynamic symbol table does not begin in usable loaded-image memory.
    #[error("ELF dynamic symbol table extends outside the loaded image")]
    SymbolTableOutsideImage,

    /// A hash table contains invalid dimensions or indices.
    #[error("invalid ELF dynamic symbol hash table")]
    InvalidHash,

    /// Dynamic hash metadata selected a symbol index outside mapped symbol-table storage.
    #[error("ELF dynamic symbol index lies outside the mapped symbol table")]
    SymbolOutsideTable,

    /// A dynamic symbol name offset lies outside the validated string table.
    #[error("ELF dynamic symbol name offset is outside the string table")]
    InvalidNameOffset,

    /// A dynamic symbol string reaches the end of the validated table without a terminator.
    #[error("ELF dynamic symbol name lacks a terminator inside the string table")]
    MissingNameTerminator,

    /// Checked runtime or target-width address arithmetic overflowed.
    #[error("ELF dynamic symbol address arithmetic overflow")]
    AddressOverflow,

    /// A dynamic pointer resolved outside every validated load segment.
    #[error("ELF dynamic pointer {0:#x} is outside the loaded image")]
    PointerOutsideImage(u64),

    /// The selected dynamic table address lies outside every validated load segment.
    #[error("ELF dynamic table at {0:?} is outside the loaded image")]
    DynamicTableOutsideImage(ViAddr),

    /// Catalejo could not open a required foreign object.
    #[error(transparent)]
    Access(#[from] AccessError),

    /// A protected process read failed.
    #[error(transparent)]
    Read(#[from] ReadError),

    /// An ELF foreign-record lift failed.
    #[error("ELF dynamic record lift failed at {address:?} with {source}")]
    Lift {
        /// Foreign record address.
        address: ViAddr,

        /// ELF record construction failure.
        #[source]
        source: ElfError,
    },

    /// ELF symbol address classification failed.
    #[error(transparent)]
    Symbol(#[from] SymbolError),
}

impl DynamicSymbolsError {
    /// Wrap process-access failure without discarding its typed address context.
    #[inline]
    const fn access(target_error: AccessError) -> Self {
        Self::Access(target_error)
    }
}

/// ELF32 dynamic-symbol lookup context.
pub type Elf32DynamicSymbols = DynamicSymbols<Elf32>;

/// ELF64 dynamic-symbol lookup context.
pub type Elf64DynamicSymbols = DynamicSymbols<Elf64>;

/// Compatibility name for ELF32 dynamic-symbol lookup failures.
pub type Elf32DynamicSymbolsError = DynamicSymbolsError;

/// Compatibility name for ELF64 dynamic-symbol lookup failures.
pub type Elf64DynamicSymbolsError = DynamicSymbolsError;

#[cfg(test)]
mod tests {
    //! Regression coverage for class-shared ELF symbol hash functions and bloom geometry.

    use super::*;

    #[test]
    fn gnu_hash_matches_known_value_for_both_classes() {
        assert_eq!(Elf32DynamicSymbols::gnu_hash(b"printf"), 0x156b_2bb8);
        assert_eq!(Elf64DynamicSymbols::gnu_hash(b"printf"), 0x156b_2bb8);
    }

    #[test]
    fn sysv_hash_matches_known_value_for_both_classes() {
        assert_eq!(Elf32DynamicSymbols::sysv_hash(b"printf"), 0x0779_05a6);
        assert_eq!(Elf64DynamicSymbols::sysv_hash(b"printf"), 0x0779_05a6);
    }

    #[test]
    fn class_word_width_selects_gnu_bloom_geometry() {
        assert_eq!(Elf32::BITS, 32);
        assert_eq!(mem::size_of::<<Elf32 as Class>::Word>(), 4);
        assert_eq!(Elf64::BITS, 64);
        assert_eq!(mem::size_of::<<Elf64 as Class>::Word>(), 8);
    }
}
