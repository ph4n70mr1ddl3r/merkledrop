// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/// @title MerkleAirdropToken
/// @notice ERC20 token with on-claim minting gated by a Merkle whitelist
/// @dev Uses keccak256(abi.encode(index, address)) for leaf encoding
contract MerkleAirdropToken {
    // --- ERC20 storage ---
    string private constant _NAME = "Merkle Airdrop Token";
    string private constant _SYMBOL = "MAT";
    uint8 private constant _DECIMALS = 18;
    uint256 private _totalSupply;
    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;

    // --- Ownership ---
    address public owner;
    address public pendingOwner;

    // --- Reentrancy guard ---
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;
    uint256 private _locked;

    // --- Airdrop config ---
    bytes32 public immutable merkleRoot;
    uint256 public immutable claimAmount;
    uint256 public immutable maxSupply;
    bool public airdropEnded;

    // --- Claim bitmap (index => claimed) ---
    // Each uint256 word stores 256 claim status bits (indexes 0-255 per word)
    mapping(uint256 => uint256) private claimedBitMap;

    // --- Events ---
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferInitiated(address indexed currentOwner, address indexed pendingOwner);
    event Claimed(uint256 indexed index, address indexed account, uint256 amount);
    event AirdropEnded(address indexed endedBy, uint256 timestamp);
    event TokensRecovered(address indexed token, address indexed to, uint256 amount);
    event ETHRecovered(address indexed to, uint256 amount);

    // --- Modifiers ---
    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier nonReentrant() {
        require(_locked == _NOT_ENTERED, "reentrant call");
        _locked = _ENTERED;
        _;
        _locked = _NOT_ENTERED;
    }

    /// @param _merkleRoot The Merkle root hash for proof verification
    /// @param _claimAmount The amount of tokens to claim per address
    /// @param _maxSupply Maximum total supply (typically leafCount * claimAmount)
    constructor(bytes32 _merkleRoot, uint256 _claimAmount, uint256 _maxSupply) {
        require(_claimAmount > 0, "claim amount must be > 0");
        require(_merkleRoot != bytes32(0), "invalid merkle root");
        require(_maxSupply > 0, "max supply must be > 0");
        owner = msg.sender;
        _locked = _NOT_ENTERED;
        merkleRoot = _merkleRoot;
        claimAmount = _claimAmount;
        maxSupply = _maxSupply;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    // --- ERC20 view functions ---
    /// @notice Returns the name of the token
    /// @return The token name
    function name() external pure returns (string memory) {
        return _NAME;
    }

    /// @notice Returns the symbol of the token
    /// @return The token symbol
    function symbol() external pure returns (string memory) {
        return _SYMBOL;
    }

    /// @notice Returns the number of decimals used by the token
    /// @return The token decimals
    function decimals() external pure returns (uint8) {
        return _DECIMALS;
    }

    /// @notice Returns the total supply of the token
    /// @return The total token supply
    function totalSupply() external view returns (uint256) {
        return _totalSupply;
    }

    /// @notice Returns the token balance of an account
    /// @param account The address to query
    /// @return The token balance of the account
    function balanceOf(address account) external view returns (uint256) {
        return _balances[account];
    }

    // --- ERC20 core ---
    /// @notice Transfers tokens to a specified address
    /// @param to The address to transfer to
    /// @param value The amount to transfer
    /// @return bool True if successful
    function transfer(address to, uint256 value) external returns (bool) {
        _transfer(msg.sender, to, value);
        return true;
    }

    /// @notice Transfers tokens from one address to another using allowance
    /// @param from The address to transfer from
    /// @param to The address to transfer to
    /// @param value The amount to transfer
    /// @return bool True if successful
    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        uint256 allowed = _allowances[from][msg.sender];
        require(allowed >= value, "allowance exceeded");
        if (allowed != type(uint256).max) {
            _allowances[from][msg.sender] = allowed - value;
        }
        _transfer(from, to, value);
        return true;
    }

    /// @notice Approves a spender to spend tokens on behalf of the owner
    /// @param spender The address to approve
    /// @param value The amount to approve
    /// @return bool True if successful
    function approve(address spender, uint256 value) external returns (bool) {
        _approve(msg.sender, spender, value);
        return true;
    }

    /// @notice Returns the remaining allowance for a spender
    /// @param owner The token owner
    /// @param spender The approved spender
    /// @return uint256 The remaining allowance
    function allowance(address owner, address spender) external view returns (uint256) {
        return _allowances[owner][spender];
    }

    // --- Airdrop logic ---
    /// @notice Claim tokens for an address using a Merkle proof
    /// @param index The index of the address in the Merkle tree
    /// @param account The address claiming tokens
    /// @param merkleProof The Merkle proof for the address
    function claim(uint256 index, address account, bytes32[] calldata merkleProof) external nonReentrant {
        require(!airdropEnded, "airdrop has ended");
        require(account != address(0), "invalid account address");
        require(!_isClaimed(index), "address already claimed");

        bytes32 leaf = keccak256(abi.encode(index, account));
        require(MerkleProof.verify(merkleProof, merkleRoot, leaf), "invalid merkle proof");

        _setClaimed(index);
        _mint(account, claimAmount);
        emit Claimed(index, account, claimAmount);
    }

    /// @notice Check if an index has been claimed
    /// @param index The index to check
    /// @return bool True if the index has been claimed
    function isClaimed(uint256 index) external view returns (bool) {
        return _isClaimed(index);
    }

    /// @notice End the airdrop, preventing further claims
    /// @dev Only callable by the owner
    function endAirdrop() external onlyOwner {
        require(!airdropEnded, "already ended");
        airdropEnded = true;
        emit AirdropEnded(msg.sender, block.timestamp);
    }

    /// @notice Recover ERC20 tokens accidentally sent to the contract
    /// @param token The token address to recover
    /// @param to The address to send recovered tokens to
    /// @param amount The amount to recover
    function recoverTokens(address token, address to, uint256 amount) external onlyOwner {
        require(to != address(0), "cannot recover to zero address");
        require(token != address(this), "cannot recover own token");
        require(IERC20(token).balanceOf(address(this)) >= amount, "insufficient balance");
        IERC20(token).transfer(to, amount);
        emit TokensRecovered(token, to, amount);
    }

    /// @notice Recover ETH accidentally sent to the contract
    /// @param to The address to send recovered ETH to
    /// @param amount The amount to recover
    function recoverETH(address payable to, uint256 amount) external onlyOwner {
        require(to != address(0), "cannot recover to zero address");
        require(address(this).balance >= amount, "insufficient ETH balance");
        (bool success, ) = to.call{value: amount}("");
        require(success, "ETH transfer failed");
        emit ETHRecovered(to, amount);
    }

    // --- Ownership ---
    /// @notice Initiate ownership transfer to a new owner
    /// @param newOwner The address to transfer ownership to
    /// @dev The new owner must call acceptOwnership to complete the transfer
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "cannot transfer to zero address");
        require(newOwner != owner, "already owner");
        pendingOwner = newOwner;
        emit OwnershipTransferInitiated(owner, newOwner);
    }

    /// @notice Accept pending ownership transfer
    /// @dev Only callable by the pending owner
    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "caller is not pending owner");
        address previousOwner = owner;
        owner = msg.sender;
        pendingOwner = address(0);
        emit OwnershipTransferred(previousOwner, msg.sender);
    }

    /// @notice Cancel a pending ownership transfer
    /// @dev Only callable by the owner
    function cancelOwnershipTransfer() external onlyOwner {
        require(pendingOwner != address(0), "no pending transfer");
        pendingOwner = address(0);
        emit OwnershipTransferInitiated(owner, address(0));
    }

    // --- Internal ERC20 helpers ---
    function _transfer(address from, address to, uint256 value) internal {
        require(to != address(0), "transfer to zero");
        uint256 fromBal = _balances[from];
        require(fromBal >= value, "insufficient balance");
        unchecked {
            _balances[from] = fromBal - value;
            _balances[to] += value;
        }
        emit Transfer(from, to, value);
    }

    function _approve(address owner, address spender, uint256 value) internal {
        require(spender != address(0), "approve to zero");
        _allowances[owner][spender] = value;
        emit Approval(owner, spender, value);
    }

    function _mint(address to, uint256 value) internal {
        require(to != address(0), "mint to zero");
        require(_totalSupply <= maxSupply - value, "exceeds max supply");
        unchecked {
            _totalSupply += value;
            _balances[to] += value;
        }
        emit Transfer(address(0), to, value);
    }

    // --- Claim bitmap helpers ---
    /// @param index The leaf index in the Merkle tree
    /// @return bool True if the index has been claimed
    function _isClaimed(uint256 index) internal view returns (bool) {
        uint256 wordIndex = index >> 8;
        uint256 bitIndex = index & 0xff;
        uint256 word = claimedBitMap[wordIndex];
        uint256 mask = 1 << bitIndex;
        return (word & mask) == mask;
    }

    /// @param index The leaf index in the Merkle tree to mark as claimed
    function _setClaimed(uint256 index) internal {
        uint256 wordIndex = index >> 8;
        uint256 bitIndex = index & 0xff;
        claimedBitMap[wordIndex] |= 1 << bitIndex;
    }
}

/// @title MerkleProof
/// @notice Minimal Merkle proof verification library (sorted pair hashing)
/// @dev Uses sorted pair hashing: keccak256(abi.encodePacked(min(a,b), max(a,b)))
library MerkleProof {
    /// @notice Verify a Merkle proof against a root hash
    /// @param proof The array of sibling hashes forming the proof
    /// @param root The Merkle root hash to verify against
    /// @param leaf The leaf hash (keccak256(abi.encode(index, address)))
    /// @return bool True if the proof is valid
    function verify(bytes32[] calldata proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        return processProof(proof, leaf) == root;
    }

    /// @notice Process a Merkle proof by hashing leaf with each proof element
    /// @param proof The array of sibling hashes forming the proof
    /// @param leaf The leaf hash to start from
    /// @return bytes32 The computed root hash from the proof
    function processProof(bytes32[] calldata proof, bytes32 leaf) internal pure returns (bytes32) {
        bytes32 computed = leaf;
        for (uint256 i = 0; i < proof.length; ) {
            computed = _hashPair(computed, proof[i]);
            unchecked {
                ++i;
            }
        }
        return computed;
    }

    /// @notice Hash a pair of values in sorted order for Merkle tree consistency
    /// @param a First hash value
    /// @param b Second hash value
    /// @return bytes32 keccak256 of sorted pair
    function _hashPair(bytes32 a, bytes32 b) private pure returns (bytes32) {
        return a < b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }
}

/// @title IERC20
/// @notice Minimal ERC20 interface for token recovery
interface IERC20 {
    function transfer(address to, uint256 value) external returns (bool);
}
