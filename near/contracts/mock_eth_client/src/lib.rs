use admin_controlled::Mask;
use borsh::{BorshDeserialize, BorshSerialize};
use eth_types::*;
use near_sdk::collections::UnorderedMap;
use near_sdk::{assert_self, AccountId};
use near_sdk::{env, near_bindgen, PanicOnDefault};

/// Minimal information about a header.
#[derive(Default, BorshDeserialize, BorshSerialize)]
pub struct HeaderInfo {
    pub total_difficulty: U256,
    pub parent_hash: H256,
    pub number: u64,
}

const PAUSE_ADD_BLOCK_HEADER: Mask = 1;

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
pub struct EthClient {
    /// Hash of the header that has the highest cumulative difficulty. The current head of the
    /// canonical chain.
    best_header_hash: H256,
    /// We store the hashes of the blocks for the past `hashes_gc_threshold` headers.
    /// Events that happen past this threshold cannot be verified by the client.
    /// It is desirable that this number is larger than 7 days worth of headers, which is roughly
    /// 40k Ethereum blocks. So this number should be 40k in production.
    hashes_gc_threshold: u64,
    /// We store full information about the headers for the past `finalized_gc_threshold` blocks.
    /// This is required to be able to adjust the canonical chain when the fork switch happens.
    /// The commonly used number is 500 blocks, so this number should be 500 in production.
    finalized_gc_threshold: u64,
    /// Number of confirmations that applications can use to consider the transaction safe.
    /// For most use cases 25 should be enough, for super safe cases it should be 500.
    num_confirmations: u64,
    /// Hashes of the canonical chain mapped to their numbers. Stores up to `hashes_gc_threshold`
    /// entries.
    /// header number -> header hash
    canonical_header_hashes: UnorderedMap<u64, H256>,
    /// All known header hashes. Stores up to `finalized_gc_threshold`.
    /// header number -> hashes of all headers with this number.
    all_header_hashes: UnorderedMap<u64, Vec<H256>>,
    /// Known headers. Stores up to `finalized_gc_threshold`.
    headers: UnorderedMap<H256, BlockHeader>,
    /// Minimal information about the headers, like cumulative difficulty. Stores up to
    /// `finalized_gc_threshold`.
    infos: UnorderedMap<H256, HeaderInfo>,
    /// If set, block header added by trusted signer will skip validation and added by
    /// others will be immediately rejected, used in PoA testnets
    trusted_signer: AccountId,
    /// Mask determining all paused functions
    paused: Mask,
}

#[near_bindgen]
impl EthClient {
    #[init]
    pub fn init(
        #[serializer(borsh)] first_header: Vec<u8>,
        #[serializer(borsh)] hashes_gc_threshold: u64,
        #[serializer(borsh)] finalized_gc_threshold: u64,
        #[serializer(borsh)] num_confirmations: u64,
        #[serializer(borsh)] trusted_signer: AccountId,
    ) -> Self {
        assert!(!Self::initialized(), "Already initialized");
        let header: BlockHeader = rlp::decode(first_header.as_slice()).unwrap();
        let header_hash = header.hash.unwrap();
        let header_number = header.number;
        let mut res = Self {
            best_header_hash: header_hash,
            hashes_gc_threshold,
            finalized_gc_threshold,
            num_confirmations,
            canonical_header_hashes: UnorderedMap::new(b"c".to_vec()),
            all_header_hashes: UnorderedMap::new(b"a".to_vec()),
            headers: UnorderedMap::new(b"h".to_vec()),
            infos: UnorderedMap::new(b"i".to_vec()),
            trusted_signer,
            paused: Mask::default(),
        };
        res.canonical_header_hashes
            .insert(&header_number, &header_hash);
        res.all_header_hashes
            .insert(&header_number, &vec![header_hash]);
        res.headers.insert(&header_hash, &header);
        res.infos.insert(
            &header_hash,
            &HeaderInfo {
                total_difficulty: Default::default(),
                parent_hash: Default::default(),
                number: header_number,
            },
        );
        res
    }

    #[result_serializer(borsh)]
    pub fn initialized() -> bool {
        env::state_read::<EthClient>().is_some()
    }

    #[result_serializer(borsh)]
    pub fn last_block_number(&self) -> u64 {
        self.infos
            .get(&self.best_header_hash)
            .unwrap_or_default()
            .number
    }

    /// Returns the block hash from the canonical chain.
    #[result_serializer(borsh)]
    pub fn block_hash(&self, #[serializer(borsh)] index: u64) -> Option<H256> {
        self.canonical_header_hashes.get(&index)
    }

    /// Returns all hashes known for that height.
    #[result_serializer(borsh)]
    pub fn known_hashes(&self, #[serializer(borsh)] index: u64) -> Vec<H256> {
        self.all_header_hashes.get(&index).unwrap_or_default()
    }

    /// Returns block hash and the number of confirmations.
    #[result_serializer(borsh)]
    pub fn block_hash_safe(&self, #[serializer(borsh)] index: u64) -> Option<H256> {
        let header_hash = self.block_hash(index)?;
        let last_block_number = self.last_block_number();
        if index + self.num_confirmations > last_block_number {
            None
        } else {
            Some(header_hash)
        }
    }

    /// Add the block header to the client.
    /// `block_header` -- RLP-encoded Ethereum header;
    #[result_serializer(borsh)]
    pub fn add_block_header(&mut self, #[serializer(borsh)] block_header: Vec<u8>) {
        env::log_str("Add block header");
        self.check_not_paused(PAUSE_ADD_BLOCK_HEADER);
        let header: BlockHeader = rlp::decode(block_header.as_slice()).unwrap();
        assert_eq!(
            &env::signer_account_id(),
            &self.trusted_signer,
            "Eth-client is deployed as trust mode, only trusted_signer can add a new header"
        );
        self.record_header(header);
    }

    pub fn update_trusted_signer(&mut self, trusted_signer: AccountId) {
        assert_self();
        self.trusted_signer = trusted_signer;
    }

    pub fn get_trusted_signer(&self) -> AccountId {
        self.trusted_signer.clone()
    }
}

impl EthClient {
    /// Record the header. If needed update the canonical chain and perform the GC.
    fn record_header(&mut self, header: BlockHeader) {
        env::log_str("Record header");
        let best_info = self.infos.get(&self.best_header_hash).unwrap();
        let header_hash = header.hash.unwrap();
        let header_number = header.number;
        if header_number + self.finalized_gc_threshold < best_info.number {
            panic!("Header is too old to have a chance to appear on the canonical chain.");
        }
        let parent_info = self
            .infos
            .get(&header.parent_hash)
            .expect("Header has unknown parent. Parent should be submitted first.");
        // Record this header in `all_hashes`.
        let mut all_hashes = self
            .all_header_hashes
            .get(&header_number)
            .unwrap_or_default();
        assert!(
            !all_hashes.iter().any(|x| *x == header_hash),
            "Header is already known. Number: {}",
            header_number
        );
        all_hashes.push(header_hash);
        self.all_header_hashes.insert(&header_number, &all_hashes);
        env::log_str("Inserting header");
        // Record full information about this header.
        self.headers.insert(&header_hash, &header);
        let info = HeaderInfo {
            total_difficulty: parent_info.total_difficulty + header.difficulty,
            parent_hash: header.parent_hash,
            number: header_number,
        };
        self.infos.insert(&header_hash, &info);
        env::log_str("Inserted");
        // Check if canonical chain needs to be updated.
        if info.total_difficulty > best_info.total_difficulty
            || (info.total_difficulty == best_info.total_difficulty
                && header.difficulty % 2 == U256::default())
        {
            env::log_str("Canonical chain needs to be updated.");
            // If the new header has a lower number than the previous header, we need to clean it
            // going forward.
            if best_info.number > info.number {
                for number in info.number + 1..=best_info.number {
                    self.canonical_header_hashes.remove(&number);
                }
            }
            // Replacing the global best header hash.
            self.best_header_hash = header_hash;
            self.canonical_header_hashes
                .insert(&header_number, &header_hash);
            // Replacing past hashes until we converge into the same parent.
            // Starting from the parent hash.
            let mut number = header.number - 1;
            let mut current_hash = info.parent_hash;
            loop {
                let prev_value = self.canonical_header_hashes.insert(&number, &current_hash);
                // If the current block hash is 0 (unlikely), or the previous hash matches the
                // current hash, then the chains converged and we can stop now.
                if number == 0 || prev_value == Some(current_hash) {
                    break;
                }
                // Check if there is an info to get the parent hash
                if let Some(info) = self.infos.get(&current_hash) {
                    current_hash = info.parent_hash;
                } else {
                    break;
                }
                number -= 1;
            }
            if header_number >= self.hashes_gc_threshold {
                self.gc_canonical_chain(header_number - self.hashes_gc_threshold);
            }
            if header_number >= self.finalized_gc_threshold {
                self.gc_headers(header_number - self.finalized_gc_threshold);
            }
        }
    }

    /// Remove hashes from the canonical chain that are at least as old as the given header number.
    fn gc_canonical_chain(&mut self, mut header_number: u64) {
        loop {
            if self.canonical_header_hashes.get(&header_number).is_some() {
                self.canonical_header_hashes.remove(&header_number);
                if header_number == 0 {
                    break;
                } else {
                    header_number -= 1;
                }
            } else {
                break;
            }
        }
    }

    /// Remove information about the headers that are at least as old as the given header number.
    fn gc_headers(&mut self, mut header_number: u64) {
        env::log_str(&format!("Run headers GC. Used gas: {:?}", env::used_gas()));
        while let Some(all_headers) = self.all_header_hashes.get(&header_number) {
            for hash in all_headers {
                self.headers.remove_raw(&hash.try_to_vec().unwrap());
                self.infos.remove(&hash);
            }
            self.all_header_hashes.remove(&header_number);
            if header_number == 0 {
                break;
            } else {
                header_number -= 1;
            }
        }
        env::log_str(&format!(
            "Finish headers GC. Used gas: {:?}",
            env::used_gas()
        ));
    }
}

admin_controlled::impl_admin_controlled!(EthClient, paused);
