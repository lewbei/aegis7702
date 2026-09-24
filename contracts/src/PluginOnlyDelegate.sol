pragma solidity 0.8.17;

/// @title PluginOnlyDelegate
/// @notice Contract featuring novel function selectors unmodeled by Aegis7702's built-in semantics.
///         Used to verify that ReachabilityExplorer works with arbitrary external ActionProviders.
contract PluginOnlyDelegate {
    /// @notice Unmodeled drain function: evacuateAsset(address,address)
    ///         Built-in semantics only models sweep, sweepArray, sweepTokens, sweepERC20, drainToken.
    function evacuateAsset(address token, address recipient) external {
        (bool ok, bytes memory data) = token.call(
            abi.encodeWithSignature("balanceOf(address)", address(this))
        );
        require(ok, "balanceOf failed");
        uint256 balance = abi.decode(data, (uint256));

        if (balance > 0) {
            (bool okTransfer,) = token.call(
                abi.encodeWithSignature("transfer(address,uint256)", recipient, balance)
            );
            require(okTransfer, "transfer failed");
        }
    }

    /// @notice Harmless no-op call that alters zero asset balances
    function harmlessPing() external pure returns (bytes32) {
        return keccak256("HARMLESS_PING");
    }

    /// @notice Intentionally reverting call to exercise search backtracking
    function forcedRevert() external pure {
        revert("FORCED_REVERT_BRANCH");
    }

    receive() external payable {}
    fallback() external payable {}
}
