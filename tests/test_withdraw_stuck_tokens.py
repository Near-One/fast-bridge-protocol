import brownie 


def test_receive(bridge, someone) -> None:
    someone_balance_before = someone.balance()
    bridge_balance_before = bridge.balance()
    someone.transfer(bridge, "1 ether")
    assert someone_balance_before == someone.balance()
    assert bridge_balance_before == bridge.balance()

def test_withdraw_stuck_tokens(bridge, someone, owner, token, someone_with_tokens) -> None:
    token.transfer(
        bridge, 
        token.balanceOf(someone_with_tokens), 
        {'from': someone_with_tokens}
    )

    assert token.balanceOf(someone_with_tokens) == 0
    
    with brownie.reverts(): 
        bridge.withdrawStuckTokens(token, {'from': someone})
    
    bridge_balance_before = token.balanceOf(bridge)
    bridge.withdrawStuckTokens(token, {'from': owner})

    assert token.balanceOf(owner) == bridge_balance_before