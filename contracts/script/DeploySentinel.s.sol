// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import "forge-std/Script.sol";
import "../src/Guard7702Sentinel.sol";
import "../src/MaliciousDelegate.sol";

contract DeploySentinel is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerPrivateKey);

        Guard7702Sentinel sentinel = new Guard7702Sentinel();
        console.log("Guard7702Sentinel deployed to:", address(sentinel));

        MaliciousDelegate delegate = new MaliciousDelegate();
        console.log("MaliciousDelegate deployed to:", address(delegate));

        vm.stopBroadcast();
    }
}
