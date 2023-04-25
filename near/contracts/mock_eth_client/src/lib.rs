use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::near_bindgen;

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, Default)]
pub struct EthClient {
    last_block_number: u64,
}

#[near_bindgen]
impl EthClient {
    #[result_serializer(borsh)]
    pub fn last_block_number(&self) -> u64 {
        self.last_block_number
    }

    pub fn set_last_block_number(&mut self, block_number: u64) {
        self.last_block_number = block_number
    }
}
