//! Test-only template: mints a public fungible token that calls itself "TARI", for attack tests
//! that try to pay a gift with the wrong resource.

use tari_template_lib::prelude::*;

#[template]
mod fake_token {
    use super::*;

    pub struct FakeToken {}

    impl FakeToken {
        pub fn mint(amount: Amount) -> Bucket {
            ResourceBuilder::public_fungible()
                .with_token_symbol("TARI")
                .initial_supply(amount)
        }
    }
}
