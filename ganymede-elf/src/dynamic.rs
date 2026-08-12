//! Bounded discovery and lookup of process-resident ELF dynamic symbols.
//!
//! One class-generic implementation handles ELF32 and ELF64. Dynamic values and symbol records keep
//! their selected ELF width while process addresses are produced only through checked load-bias
//! translation. System V and GNU hash traversal remain shared because their indices and chain words
//! are class-independent.

extern crate alloc;

use alloc::boxed::Box;
use core::{mem, num::NonZeroUsize};

use catalejo::{address::ViAddr, prelude::Lift};
use ganymede_process::process::{AccessError, Process, ReadError};
use num_traits::One;

use crate::{
    binding,
    class::{Class, Elf32, Elf64, ElfClass},
    image::LoadBias,
    lift::{Dynamic, ElfError},
    symbol::{DynamicSymbol, Export, Symbol, SymbolError},
};

/// Default dynamic-entry bound.
const DYNAMIC_ENTRIES: NonZeroUsize =
    const { NonZeroUsize::new(16_384).expect("dynamic-entry limit must be nonzero") };

/// Default dynamic string-table byte bound.
const STRING_BYTES: NonZeroUsize =
    const { NonZeroUsize::new(16 * 1024 * 1024).expect("string byte limit must be nonzero") };

/// Default hash traversal bound.
const HASH_STEPS: NonZeroUsize =
    const { NonZeroUsize::new(1_048_576).expect("hash step limit must be nonzero") };

/// Default dynamic symbol-index bound.
const SYMBOL_INDICES: NonZeroUsize =
    const { NonZeroUsize::new(1_048_576).expect("symbol-index limit must be nonzero") };

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

/// Finite policy for dynamic-table and symbol lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// NOTE(invariant): Every bound is nonzero, so all foreign traversals permit useful work while remaining finite for either ELF class.
pub struct SymbolLimits {
    /// Maximum dynamic-table entries read before requiring `DT_NULL`.
    dynamic_entries: NonZeroUsize,

    /// Maximum bytes accepted for the complete dynamic string table.
    string_bytes: NonZeroUsize,

    /// Maximum hash-chain steps permitted for one symbol lookup.
    hash_steps: NonZeroUsize,

    /// Maximum dynamic symbol index accepted from hash metadata.
    symbol_indices: NonZeroUsize,
}

impl SymbolLimits {
    /// Construct finite dynamic-symbol lookup policy.
    #[inline]
    #[must_use]
    pub const fn new(
        target_dynamic_entries: NonZeroUsize,
        target_string_bytes: NonZeroUsize,
        target_hash_steps: NonZeroUsize,
        target_symbol_indices: NonZeroUsize,
    ) -> Self {
        Self {
            dynamic_entries: target_dynamic_entries,
            string_bytes: target_string_bytes,
            hash_steps: target_hash_steps,
            symbol_indices: target_symbol_indices,
        }
    }

    /// Return the conservative default policy shared by ELF32 and ELF64 process inspection.
    #[inline]
    #[must_use]
    pub const fn standard() -> Self {
        Self::new(DYNAMIC_ENTRIES, STRING_BYTES, HASH_STEPS, SYMBOL_INDICES)
    }

    /// Return the default policy through the ELF32 compatibility profile.
    #[inline]
    #[must_use]
    pub const fn elf32() -> Self {
        Self::standard()
    }

    /// Return the default policy through the ELF64 compatibility profile.
    #[inline]
    #[must_use]
    pub const fn elf64() -> Self {
        Self::standard()
    }

    /// Return the dynamic-entry limit.
    #[inline]
    #[must_use]
    pub const fn dynamic_entries(&self) -> NonZeroUsize {
        let Self {
            dynamic_entries, ..
        } = self;

        *dynamic_entries
    }

    /// Return the string-table byte limit.
    #[inline]
    #[must_use]
    pub const fn string_bytes(&self) -> NonZeroUsize {
        let Self { string_bytes, .. } = self;

        *string_bytes
    }

    /// Return the hash-chain step limit.
    #[inline]
    #[must_use]
    pub const fn hash_steps(&self) -> NonZeroUsize {
        let Self { hash_steps, .. } = self;

        *hash_steps
    }

    /// Return the maximum accepted dynamic symbol index.
    #[inline]
    #[must_use]
    pub const fn symbol_indices(&self) -> NonZeroUsize {
        let Self { symbol_indices, .. } = self;

        *symbol_indices
    }
}

impl Default for SymbolLimits {
    #[inline]
    fn default() -> Self {
        Self::standard()
    }
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
// NOTE(invariant): All retained table addresses come from one terminated dynamic table through the same class-width load bias, the symbol stride matches the selected raw symbol record, and the owned string table has exactly the validated `DT_STRSZ` extent.
pub struct DynamicSymbols<ClassType>
where
    ClassType: Class,
{
    /// Load bias used for symbol values and dynamic pointers.
    load_bias: LoadBias<ClassType>,

    /// Runtime dynamic symbol table address.
    symbol_table: ViAddr,

    /// Owned dynamic string table bytes.
    string_table: Box<[u8]>,

    /// Hash mechanism that bounds and indexes symbol lookup.
    hash_table: HashTable,

    /// Finite lookup policy retained for on-demand hash traversal.
    limits: SymbolLimits,
}

impl<ClassType> DynamicSymbols<ClassType>
where
    ClassType: Class,
    Dynamic<ClassType>: Lift<Value = ClassType::Dynamic, Context = (), Error = ElfError>,
    Symbol<ClassType>: Lift<Value = ClassType::Symbol, Context = (), Error = ElfError>,
{
    /// Discover dynamic symbol metadata from one process-resident ELF dynamic table.
    ///
    /// Dynamic pointers remain class-sized until translated by the supplied load bias. GNU hash
    /// bloom reads use the selected class word while bucket and chain words remain 32-bit as defined
    /// by the GNU hash format.
    ///
    /// # Errors
    ///
    /// This returns an error for malformed or incomplete dynamic metadata, unsupported hash layout,
    /// target or process address overflow, policy violations, foreign access failure, or protected
    /// read faults.
    #[inline]
    pub fn read(
        target_process: &Process,
        target_load_bias: LoadBias<ClassType>,
        target_dynamic: ViAddr,
        target_limits: SymbolLimits,
    ) -> Result<Self, DynamicSymbolsError> {
        let stride = u64::try_from(mem::size_of::<ClassType::Dynamic>())
            .map_err(|_| DynamicSymbolsError::InvalidClassLayout(ClassType::CLASS))?;
        let mut string_table_virtual = None;
        let mut string_table_size = None;
        let mut symbol_table_virtual = None;
        let mut symbol_stride = None;
        let mut sysv_hash_virtual = None;
        let mut gnu_hash_virtual = None;
        let mut terminated = false;

        for index in 0..target_limits.dynamic_entries().get() {
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
                DT_NULL => {
                    terminated = true;
                    break;
                }
                DT_STRTAB => {
                    Self::unique(&mut string_table_virtual, value, DynamicField::StringTable)?;
                }
                DT_STRSZ => {
                    Self::unique(&mut string_table_size, value, DynamicField::StringSize)?;
                }
                DT_SYMTAB => {
                    Self::unique(&mut symbol_table_virtual, value, DynamicField::SymbolTable)?;
                }
                DT_SYMENT => {
                    Self::unique(&mut symbol_stride, value, DynamicField::SymbolStride)?;
                }
                DT_HASH => {
                    Self::unique(&mut sysv_hash_virtual, value, DynamicField::SysvHash)?;
                }
                DT_GNU_HASH => {
                    Self::unique(&mut gnu_hash_virtual, value, DynamicField::GnuHash)?;
                }
                _ => {}
            }
        }

        if !terminated {
            return Err(DynamicSymbolsError::MissingTerminator);
        }

        let string_table_virtual =
            string_table_virtual.ok_or(DynamicSymbolsError::Missing(DynamicField::StringTable))?;
        let string_table_size =
            string_table_size.ok_or(DynamicSymbolsError::Missing(DynamicField::StringSize))?;
        let symbol_table_virtual =
            symbol_table_virtual.ok_or(DynamicSymbolsError::Missing(DynamicField::SymbolTable))?;
        let symbol_stride =
            symbol_stride.ok_or(DynamicSymbolsError::Missing(DynamicField::SymbolStride))?;
        let host_symbol_stride = u64::try_from(mem::size_of::<ClassType::Symbol>())
            .map_err(|_| DynamicSymbolsError::InvalidClassLayout(ClassType::CLASS))?;
        let expected_stride = ClassType::Word::try_from(host_symbol_stride)
            .ok()
            .ok_or(DynamicSymbolsError::InvalidClassLayout(ClassType::CLASS))?;

        if symbol_stride != expected_stride {
            return Err(DynamicSymbolsError::InvalidSymbolStride(
                symbol_stride.into(),
            ));
        }

        let string_size: usize = string_table_size
            .try_into()
            .map_err(|_| DynamicSymbolsError::StringTableTooLarge(string_table_size.into()))?;

        if string_size > target_limits.string_bytes().get() {
            return Err(DynamicSymbolsError::StringTableTooLarge(
                string_table_size.into(),
            ));
        }

        let string_table = target_load_bias
            .address(string_table_virtual)
            .ok_or(DynamicSymbolsError::AddressOverflow)?;
        let symbol_table = target_load_bias
            .address(symbol_table_virtual)
            .ok_or(DynamicSymbolsError::AddressOverflow)?;
        let string_table = Process::read_bytes(target_process, string_table, string_size)?;
        let string_table = string_table.into_boxed_slice();
        let hash_table = Self::hash(
            target_process,
            target_load_bias,
            sysv_hash_virtual,
            gnu_hash_virtual,
            target_limits,
        )?;

        Ok(Self {
            load_bias: target_load_bias,
            symbol_table,
            string_table,
            hash_table,
            limits: target_limits,
        })
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
        let Self {
            hash_table, limits, ..
        } = self;
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

        for _step in 0..limits.hash_steps().get() {
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

        Err(DynamicSymbolsError::HashLimit)
    }

    /// Resolve one exact name through a validated GNU hash table.
    fn gnu(
        &self,
        target_process: &Process,
        target_name: &[u8],
    ) -> Result<Option<DynamicSymbol<ClassType>>, DynamicSymbolsError> {
        let Self { hash_table, .. } = self;
        let (address, buckets, symbol_offset, bloom_words, bloom_shift) = match hash_table {
            HashTable::Gnu {
                address,
                buckets,
                symbol_offset,
                bloom_words,
                bloom_shift,
            } => (
                *address,
                *buckets,
                *symbol_offset,
                *bloom_words,
                *bloom_shift,
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

    /// Traverse one validated GNU hash chain until a name matches or the chain terminates.
    fn chain(
        &self,
        target_process: &Process,
        target_name: &[u8],
        target_hash: u32,
        target_symbol_offset: u32,
        target_bucket: GnuBucket,
    ) -> Result<Option<DynamicSymbol<ClassType>>, DynamicSymbolsError> {
        let Self {
            limits, hash_table, ..
        } = self;
        let address = match hash_table {
            HashTable::Gnu { address, .. } => *address,
            HashTable::Sysv { .. } => return Err(DynamicSymbolsError::InvalidHash),
        };
        let GnuBucket { mut symbol, chains } = target_bucket;

        for _step in 0..limits.hash_steps().get() {
            let relative_index = symbol
                .checked_sub(target_symbol_offset)
                .ok_or(DynamicSymbolsError::InvalidHash)?;
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

        Err(DynamicSymbolsError::HashLimit)
    }

    /// Read one bounded dynamic symbol and its validated string-table name.
    fn symbol(
        &self,
        target_process: &Process,
        target_index: u32,
    ) -> Result<DynamicSymbol<ClassType>, DynamicSymbolsError> {
        let Self {
            symbol_table,
            string_table,
            limits,
            ..
        } = self;
        let index_valid = usize::try_from(target_index)
            .is_ok_and(|target_index| target_index < limits.symbol_indices().get());

        if !index_valid {
            return Err(DynamicSymbolsError::SymbolIndexLimit);
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
        let name_suffix = string_table
            .get(name_offset..)
            .ok_or(DynamicSymbolsError::InvalidNameOffset)?;
        let terminator = name_suffix
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(DynamicSymbolsError::MissingNameTerminator)?;
        let name = &name_suffix[..terminator];

        Ok(DynamicSymbol::new(target_index, symbol, name))
    }

    /// Validate the preferred available runtime symbol-hash structure.
    fn hash(
        target_process: &Process,
        target_load_bias: LoadBias<ClassType>,
        sysv_virtual: Option<ClassType::Word>,
        gnu_virtual: Option<ClassType::Word>,
        target_limits: SymbolLimits,
    ) -> Result<HashTable, DynamicSymbolsError> {
        match (gnu_virtual, sysv_virtual) {
            (Some(gnu_virtual), _) => {
                let address = target_load_bias
                    .address(gnu_virtual)
                    .ok_or(DynamicSymbolsError::AddressOverflow)?;
                let buckets = Process::read::<u32>(target_process, address)?;
                let symbol_offset = Process::read::<u32>(
                    target_process,
                    Self::add(address, GNU_HASH_SYMBOL_OFFSET)?,
                )?;
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
                let bloom_shift_valid = bloom_shift < u32::BITS;
                let symbol_offset_valid = usize::try_from(symbol_offset)
                    .is_ok_and(|target_index| target_index < target_limits.symbol_indices().get());

                if !bloom_shift_valid {
                    return Err(DynamicSymbolsError::InvalidHash);
                }

                if !symbol_offset_valid {
                    return Err(DynamicSymbolsError::SymbolIndexLimit);
                }

                Ok(HashTable::Gnu {
                    address,
                    buckets,
                    symbol_offset,
                    bloom_words,
                    bloom_shift,
                })
            }
            (None, Some(sysv_virtual)) => {
                let address = target_load_bias
                    .address(sysv_virtual)
                    .ok_or(DynamicSymbolsError::AddressOverflow)?;
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

                if symbols.get() > target_limits.symbol_indices().get() {
                    return Err(DynamicSymbolsError::SymbolIndexLimit);
                }

                Ok(HashTable::Sysv {
                    address,
                    buckets,
                    symbols,
                })
            }
            (None, None) => Err(DynamicSymbolsError::MissingHash),
        }
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
    /// The bounded dynamic table had no `DT_NULL` terminator.
    #[error("ELF dynamic table has no terminator within the configured bound")]
    MissingTerminator,

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

    /// `DT_STRSZ` exceeds the configured string-table policy.
    #[error("ELF dynamic string table is too large at {0} bytes")]
    StringTableTooLarge(u64),

    /// A hash table contains invalid dimensions or indices.
    #[error("invalid ELF dynamic symbol hash table")]
    InvalidHash,

    /// One hash lookup exceeded the configured traversal bound.
    #[error("ELF dynamic symbol hash traversal exceeded its configured bound")]
    HashLimit,

    /// Dynamic hash metadata selected a symbol index outside configured policy.
    #[error("ELF dynamic symbol index exceeds the configured bound")]
    SymbolIndexLimit,

    /// A dynamic symbol name offset lies outside the validated string table.
    #[error("ELF dynamic symbol name offset is outside the string table")]
    InvalidNameOffset,

    /// A dynamic symbol string reaches the end of the validated table without a terminator.
    #[error("ELF dynamic symbol name lacks a terminator inside the string table")]
    MissingNameTerminator,

    /// Checked runtime or target-width address arithmetic overflowed.
    #[error("ELF dynamic symbol address arithmetic overflow")]
    AddressOverflow,

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

/// Compatibility name for the former ELF64-specific lookup policy.
pub type Elf64SymbolLimits = SymbolLimits;

/// ELF32 lookup policy alias matching the class-specific public vocabulary.
pub type Elf32SymbolLimits = SymbolLimits;

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
