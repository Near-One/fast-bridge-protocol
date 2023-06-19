use near_plugins::access_control_any;
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{env, AccountId};

use crate::*;

#[derive(BorshDeserialize, BorshSerialize, Deserialize, Serialize, Debug, PartialEq)]
#[serde(crate = "near_sdk::serde")]
pub enum WhitelistMode {
    Blocked,
    CheckToken,
    CheckAccountAndToken,
}

fn get_token_account_key(token: Option<&AccountId>, account: &AccountId) -> String {
    if let Some(token) = token {
        format!("{}:{}", token, account)
    } else {
        account.to_string()
    }
}

#[near_bindgen]
impl FastBridge {
    #[access_control_any(roles(Role::WhitelistManager, Role::DAO))]
    pub fn set_token_whitelist_mode(&mut self, token: AccountId, mode: WhitelistMode) {
        self.whitelist_tokens.insert(&token, &mode);
    }

    #[access_control_any(roles(Role::WhitelistManager, Role::DAO))]
    pub fn add_token_to_account_whitelist(&mut self, token: Option<AccountId>, account: AccountId) {
        if let Some(token) = &token {
            assert!(
                self.whitelist_tokens.get(token).is_some(),
                "The whitelisted token mode is not set",
            );
        }

        self.whitelist_accounts
            .insert(&get_token_account_key(token.as_ref(), &account));
    }

    #[access_control_any(roles(Role::WhitelistManager, Role::DAO))]
    pub fn remove_token_from_account_whitelist(
        &mut self,
        token: Option<AccountId>,
        account: AccountId,
    ) -> bool {
        self.whitelist_accounts
            .remove(&get_token_account_key(token.as_ref(), &account))
    }

    pub fn check_whitelist_token_and_account(&self, token: &AccountId, account: &AccountId) {
        if !self.is_whitelist_mode_enabled {
            return;
        }

        let token_whitelist_mode = self.whitelist_tokens.get(token).unwrap_or_else(|| {
            env::panic_str(format!("The token `{}` is not whitelisted", token).as_str())
        });

        match token_whitelist_mode {
            WhitelistMode::CheckAccountAndToken => {
                let token_account_key = get_token_account_key(Some(token), account);
                require!(
                    self.whitelist_accounts.contains(&token_account_key)
                        || self.whitelist_accounts.contains(&account.to_string()),
                    format!(
                        "The token `{}` isn't whitelisted for the account `{}`",
                        token, account
                    ),
                );
            }
            // No action is needed for CheckToken, as the token is already checked in whitelist_tokens
            WhitelistMode::CheckToken => {}
            WhitelistMode::Blocked => {
                env::panic_str(format!("The token `{}` is blocked", token).as_str())
            }
        }
    }

    #[access_control_any(roles(Role::WhitelistManager, Role::DAO))]
    pub fn set_whitelist_mode_enabled(&mut self, enabled: bool) {
        self.is_whitelist_mode_enabled = enabled;
    }

    pub fn get_whitelist_tokens(&self) -> Vec<(AccountId, WhitelistMode)> {
        self.whitelist_tokens.iter().collect::<Vec<_>>()
    }

    pub fn get_whitelist_accounts(&self) -> Vec<String> {
        self.whitelist_accounts.iter().collect::<Vec<_>>()
    }
}
