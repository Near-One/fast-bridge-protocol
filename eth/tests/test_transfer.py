import brownie 

def test_transfer(bridge, relayer, someone, owner, token) -> None:
    # Add token to whitelist.
    bridge.setWhitelistedTokens(
        [token],
        [True],
        {'from': owner}
    )
    token.approve(
        bridge, 
        token.balanceOf(relayer), 
        {'from': relayer}
    )
    part_of_transfer = token.balanceOf(relayer) - 100

    bridge.transferTokens(
        token, 
        someone, 
        11231231, 
        part_of_transfer, 
        {'from': relayer}
    )
    
    assert token.balanceOf(someone) == part_of_transfer

    bridge.pause({'from': owner})
    with brownie.reverts('Pausable: paused'):
        bridge.transferTokens(
            token,
            someone,
            11231232,
            token.balanceOf(relayer),
            {'from': relayer} 
        )

    bridge.unPause({'from': owner})

    bridge.transferTokens(
        token, 
        someone, 
        11231232, 
        100, 
        {'from': relayer}
    )

    assert token.balanceOf(someone) == part_of_transfer + 100


def test_two_equal_transfers(
    bridge, 
    relayer, 
    another_relayer,
    someone, 
    owner, 
    token
    ) -> None:
    # Add token to whitelist.
    bridge.setWhitelistedTokens(
        [token],
        [True],
        {'from': owner}
    )
    token.approve(
        bridge, 
        token.balanceOf(relayer), 
        {'from': relayer}
    )
    token.approve(
        bridge, 
        token.balanceOf(another_relayer), 
        {'from': another_relayer}
    )
    relayer_balance_before = token.balanceOf(relayer)

    bridge.transferTokens(
        token, 
        someone, 
        11231231, 
        token.balanceOf(relayer), 
        {'from': relayer}
    )
    
    assert token.balanceOf(someone) == relayer_balance_before

    with brownie.reverts("This transaction has already been processed!"):
        bridge.transferTokens(
            token, 
            someone, 
            11231231, 
            relayer_balance_before, 
            {'from': another_relayer}
        )
    # Check that transfer not happend.
    assert token.balanceOf(someone) == relayer_balance_before

def test_two_NOT_equal_transfers(
    bridge, 
    relayer, 
    another_relayer,
    someone, 
    owner, 
    token
    ) -> None:
    # Add token to whitelist.
    bridge.setWhitelistedTokens(
        [token],
        [True],
        {'from': owner}
    )
    token.approve(
        bridge, 
        token.balanceOf(relayer), 
        {'from': relayer}
    )
    token.approve(
        bridge, 
        token.balanceOf(another_relayer), 
        {'from': another_relayer}
    )
    relayer_balance_before = token.balanceOf(relayer)

    bridge.transferTokens(
        token, 
        someone, 
        11231231, 
        token.balanceOf(relayer), 
        {'from': relayer}
    )
    
    assert token.balanceOf(someone) == relayer_balance_before
    # Create transfer with another nonce.
    bridge.transferTokens(
        token, 
        someone, 
        11231232, 
        relayer_balance_before, 
        {'from': another_relayer}
    )

    assert token.balanceOf(someone) == relayer_balance_before * 2
    