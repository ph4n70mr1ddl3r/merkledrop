// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/// @title MerkleAirdropToken
/// @notice ERC20 token with on-claim minting gated by a Merkle whitelist.
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

    // --- Airdrop config ---
    bytes32 public immutable merkleRoot;
    uint256 public constant CLAIM_AMOUNT = 100 ether; // 100 MAT with 18 decimals
    bool public airdropEnded;

    // --- Claim bitmap (index => claimed) ---
    mapping(uint256 => uint256) private claimedBitMap;

    // --- Events ---
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event Claimed(uint256 indexed index, address indexed account, uint256 amount);
    event AirdropEnded(address indexed endedBy, uint256 timestamp);

    // --- Modifiers ---
    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(bytes32 _merkleRoot) {
        owner = msg.sender;
        merkleRoot = _merkleRoot;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    // --- ERC20 view functions ---
    function name() external pure returns (string memory) {
        return _NAME;
    }

    function symbol() external pure returns (string memory) {
        return _SYMBOL;
    }

    function decimals() external pure returns (uint8) {
        return _DECIMALS;
    }

    function totalSupply() external view returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address account) external view returns (uint256) {
        return _balances[account];
    }

    // --- ERC20 core ---
    function transfer(address to, uint256 value) external returns (bool) {
        _transfer(msg.sender, to, value);
        return true;
    }

    function approve(address spender, uint256 value) external returns (bool) {
        _approve(msg.sender, spender, value);
        return true;
    }

    function allowance(address _owner, address spender) external view returns (uint256) {
        return _allowances[_owner][spender];
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        uint256 allowed = _allowances[from][msg.sender];
        require(allowed >= value, "allowance exceeded");
        if (allowed != type(uint256).max) {
            _allowances[from][msg.sender] = allowed - value;
        }
        _transfer(from, to, value);
        return true;
    }

    // --- Airdrop logic ---
    function claim(uint256 index, address account, bytes32[] calldata merkleProof) external {
        require(!airdropEnded, "airdrop ended");
        require(account != address(0), "bad account");
        require(!_isClaimed(index), "already claimed");

        // Leaf omits amount; amount is fixed at CLAIM_AMOUNT in the contract.
        bytes32 leaf = keccak256(abi.encodePacked(index, account));
        require(MerkleProof.verify(merkleProof, merkleRoot, leaf), "bad proof");

        _setClaimed(index);
        _mint(account, CLAIM_AMOUNT);
        emit Claimed(index, account, CLAIM_AMOUNT);
    }

    function isClaimed(uint256 index) external view returns (bool) {
        return _isClaimed(index);
    }

    function endAirdrop() external onlyOwner {
        require(!airdropEnded, "already ended");
        airdropEnded = true;
        emit AirdropEnded(msg.sender, block.timestamp);
    }

    // --- Ownership ---
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "zero owner");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
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

    function _approve(address _owner, address spender, uint256 value) internal {
        require(spender != address(0), "approve to zero");
        _allowances[_owner][spender] = value;
        emit Approval(_owner, spender, value);
    }

    function _mint(address to, uint256 value) internal {
        require(to != address(0), "mint to zero");
        _totalSupply += value;
        _balances[to] += value;
        emit Transfer(address(0), to, value);
    }

    // --- Claim bitmap helpers ---
    function _isClaimed(uint256 index) internal view returns (bool) {
        uint256 wordIndex = index >> 8; // divide by 256
        uint256 bitIndex = index & 0xff; // mod 256
        uint256 word = claimedBitMap[wordIndex];
        uint256 mask = 1 << bitIndex;
        return word & mask == mask;
    }

    function _setClaimed(uint256 index) internal {
        uint256 wordIndex = index >> 8;
        uint256 bitIndex = index & 0xff;
        claimedBitMap[wordIndex] |= 1 << bitIndex;
    }
}

/// @notice Minimal Merkle proof verification library (sorted pair hashing).
library MerkleProof {
    function verify(bytes32[] calldata proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        return processProof(proof, leaf) == root;
    }

    function processProof(bytes32[] calldata proof, bytes32 leaf) internal pure returns (bytes32) {
        bytes32 computed = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            computed = _hashPair(computed, proof[i]);
        }
        return computed;
    }

    function _hashPair(bytes32 a, bytes32 b) private pure returns (bytes32) {
        return a < b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }
}
