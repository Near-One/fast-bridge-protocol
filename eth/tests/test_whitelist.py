import brownie 


def test_add_tokens_to_whitelist(owner, bridge) -> None:
    tokens_addresses = [
        '0xdAC17F958D2ee523a2206206994597C13D831ec7',
        '0xB8c77482e45F1F44dE1745F52C74426C631bDD52',
        '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48'
    ]
    tokens_states = [
        True,
        True,
        False
    ]

    bridge.setWhitelistedTokens(
        tokens_addresses, 
        tokens_states, 
        {'from': owner})

    assert bridge.isTokenInWhitelist(
        '0xdAC17F958D2ee523a2206206994597C13D831ec7') == True
    assert bridge.isTokenInWhitelist(
        '0xB8c77482e45F1F44dE1745F52C74426C631bDD52') == True
    assert bridge.isTokenInWhitelist(
        '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48') == False

def test_access_control(someone, bridge) -> None:
    tokens_addresses = [
        '0xdAC17F958D2ee523a2206206994597C13D831ec7',
        '0xB8c77482e45F1F44dE1745F52C74426C631bDD52',
        '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48'
    ]
    tokens_states = [
        True,
        True,
        False
    ]
    with brownie.reverts():
        bridge.setWhitelistedTokens(
            tokens_addresses, 
            tokens_states, 
            {'from': someone}
            )
