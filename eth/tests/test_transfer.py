import brownie


def test_transfer(bridge, relayer, someone, owner, token, unlock_recipient) -> None:
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
        unlock_recipient,
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
            unlock_recipient,
            {'from': relayer}
        )

    bridge.unPause({'from': owner})

    bridge.transferTokens(
        token,
        someone,
        11231232,
        100,
        unlock_recipient,
        {'from': relayer}
    )

    assert token.balanceOf(someone) == part_of_transfer + 100


def test_two_equal_transfers(
    bridge,
    relayer,
    another_relayer,
    someone,
    owner,
    token,
    unlock_recipient
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
        unlock_recipient,
        {'from': relayer}
    )

    assert token.balanceOf(someone) == relayer_balance_before

    with brownie.reverts("This transaction has already been processed!"):
        bridge.transferTokens(
            token,
            someone,
            11231231,
            relayer_balance_before,
            unlock_recipient,
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
    token,
    unlock_recipient
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
        unlock_recipient,
        {'from': relayer}
    )

    assert token.balanceOf(someone) == relayer_balance_before
    # Create transfer with another nonce.
    bridge.transferTokens(
        token,
        someone,
        11231232,
        relayer_balance_before,
        unlock_recipient,
        {'from': another_relayer}
    )

    assert token.balanceOf(someone) == relayer_balance_before * 2


def test_cant_transfer_to_zero_or_self(
    bridge,
    relayer,
    another_relayer,
    someone,
    owner,
    token,
    unlock_recipient
) -> None:
    bridge.setWhitelistedTokens(
        [token],
        [True],
        {'from': owner}
    )
    # Cant transfer to zero address
    with brownie.reverts("Wrong recipient provided"):
        bridge.transferTokens(
            token,
            "0x0000000000000000000000000000000000000000",
            1,
            10000000000,
            unlock_recipient,
            {'from': relayer}
        )
    # Cant transfer to msg.sender
    with brownie.reverts("Wrong recipient provided"):
        bridge.transferTokens(
            token,
            relayer,
            1,
            10000000000,
            unlock_recipient,
            {'from': relayer}
        )


def test_cant_transfer_zero_amount(
    bridge,
    relayer,
    another_relayer,
    someone,
    owner,
    token,
    unlock_recipient
) -> None:
    bridge.setWhitelistedTokens(
        [token],
        [True],
        {'from': owner}
    )

    with brownie.reverts("Wrong amount provided"):
        bridge.transferTokens(
            token,
            someone,
            1,
            0,
            unlock_recipient,
            {'from': relayer}
        )
