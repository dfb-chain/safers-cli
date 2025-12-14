use alloy_sol_types::sol;

sol! {
    #[sol(rpc)]
    contract ProxyFactory {
        function createProxyWithNonce(address singleton, bytes initializer, uint256 saltNonce)
            external
            returns (address proxy);
    }
}

sol! {
    #[sol(rpc)]
    contract GnosisSafe {
        function setup(
            address[] owners,
            uint256 threshold,
            address to,
            bytes data,
            address fallbackHandler,
            address paymentToken,
            uint256 payment,
            address payable paymentReceiver
        ) external;
        enum Operation { Call, DelegateCall }
        function execTransaction(
            address to,
            uint256 value,
            bytes data,
            Operation operation,
            uint256 safeTxGas,
            uint256 baseGas,
            uint256 gasPrice,
            address gasPayer,
            bytes signature
        ) external returns (bool success);
        function enableModule(address module) external;
        function setGuard(address guard) external;
        function setModuleGuard(address guard) external;
        function isModuleEnabled(address module) external view returns (bool);
        function getGuard() external view returns (address);
        function getThreshold() external view returns (uint256);
        function getOwners() external view returns (address[]);
    }
}

sol! {
    #[sol(rpc)]
    contract ERC20 {
        function transfer(address to, uint256 amount) external returns (bool);
        function balanceOf(address account) external view returns (uint256);
    }
}

sol! {
    #[sol(rpc)]
    contract ERC721 {
        function safeTransferFrom(address from, address to, uint256 tokenId) external;
        function ownerOf(uint256 tokenId) external view returns (address);
    }
}

