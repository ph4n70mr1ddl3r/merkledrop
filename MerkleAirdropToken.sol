// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title MerkleAirdropToken
/// @notice ERC20 token with on-claim minting gated by a Merkle whitelist
/// @dev Uses keccak256(abi.encode(index, address)) for leaf encoding
contract MerkleAirdropToken {
    // --- Custom Error Types ---
    error InvalidClaimAmount();
    error InvalidMerkleRoot();
    error InvalidMaxSupply();
    error NotOwner();
    error ReentrantCall();
    error AirdropAlreadyEnded();
    error InvalidAccountAddress();
    error AddressAlreadyClaimed();
    error MerkleProofTooLong();
    error InvalidMerkleProof();
    error ArrayLengthMismatch();
    error InvalidBatchSize();
    error CannotTransferToZeroAddress();
    error InsufficientBalance();
    error AllowanceExceeded();
    error CannotRecoverOwnToken();
    error InsufficientTokenBalance();
    error TokenTransferFailed();
    error InsufficientETHBalance();
    error ETHTransferFailed();
    error AlreadyOwner();
    error OwnershipTransferAlreadyPending();
    error CallerIsNotPendingOwner();
    error NoPendingTransfer();
    error ExceedsMaxSupply();
    error ContractPaused();
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
    bool public paused;
    
    // --- Constants for gas optimization and safety ---
    uint256 private constant MAX_PROOF_LENGTH = 32;
    uint256 private constant MAX_ADDRESSES_PER_WORD = 256;

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
    event Paused(address indexed account, uint256 timestamp);
    event Unpaused(address indexed account, uint256 timestamp);

    // --- Modifiers ---
    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier nonReentrant() {
        if (_locked != _NOT_ENTERED) revert ReentrantCall();
        _locked = _ENTERED;
        _;
        _locked = _NOT_ENTERED;
    }

    /// @param _merkleRoot The Merkle root hash for proof verification
    /// @param _claimAmount The amount of tokens to claim per address
    /// @param _maxSupply Maximum total supply (typically leafCount * claimAmount)
    constructor(bytes32 _merkleRoot, uint256 _claimAmount, uint256 _maxSupply) {
        if (_claimAmount == 0) revert InvalidClaimAmount();
        if (_merkleRoot == bytes32(0)) revert InvalidMerkleRoot();
        if (_maxSupply == 0) revert InvalidMaxSupply();
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
    /// @dev Transfers tokens from caller to specified address with reentrancy protection
    /// @param to The address to transfer to
    /// @param value The amount of tokens to transfer
    /// @return bool Always returns true (reverts on failure)
    /// @custom:reverts CannotTransferToZeroAddress - if recipient is zero address
    /// @custom:reverts InsufficientBalance - if sender has insufficient balance
    function transfer(address to, uint256 value) external nonReentrant returns (bool) {
        _transfer(msg.sender, to, value);
        return true;
    }

    /// @notice Transfers tokens from one address to another using allowance
    /// @dev Allows spender to transfer tokens from owner's account, with reentrancy protection
    /// @param from The address to transfer from
    /// @param to The address to transfer to
    /// @param value The amount of tokens to transfer
    /// @return bool Always returns true (reverts on failure)
    /// @custom:reverts AllowanceExceeded - if transfer amount exceeds spender's allowance
    /// @custom:reverts CannotTransferToZeroAddress - if recipient is zero address
    /// @custom:reverts InsufficientBalance - if sender has insufficient balance
    function transferFrom(address from, address to, uint256 value) external nonReentrant returns (bool) {
        uint256 allowed = _allowances[from][msg.sender];
        if (allowed < value) revert AllowanceExceeded();
        if (allowed != type(uint256).max) {
            _allowances[from][msg.sender] = allowed - value;
        }
        _transfer(from, to, value);
        return true;
    }

    /// @notice Approves a spender to spend tokens on behalf of the owner
    /// @dev Sets approval amount for spender to transfer tokens from owner's account, with reentrancy protection
    /// @param spender The address to approve
    /// @param value The amount of tokens to approve
    /// @return bool Always returns true (reverts on failure)
    /// @custom:reverts CannotTransferToZeroAddress - if spender is zero address
    function approve(address spender, uint256 value) external nonReentrant returns (bool) {
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
    /// @dev Validates Merkle proof and mints claimAmount tokens to specified address
    /// @param index The index of the address in the Merkle tree
    /// @param account The address claiming tokens
    /// @param merkleProof The Merkle proof for the address
    /// @custom:reverts ContractPaused - if contract is paused
    /// @custom:reverts AirdropAlreadyEnded - if airdrop has already ended
    /// @custom:reverts InvalidAccountAddress - if account is zero address
    /// @custom:reverts AddressAlreadyClaimed - if the address has already claimed tokens
    /// @custom:reverts MerkleProofTooLong - if proof exceeds 32 elements (gas limit)
    /// @custom:reverts InvalidMerkleProof - if proof does not verify against merkle root
    function claim(uint256 index, address account, bytes32[] calldata merkleProof) external nonReentrant {
        if (paused) revert ContractPaused();
        if (airdropEnded) revert AirdropAlreadyEnded();
        if (account == address(0)) revert InvalidAccountAddress();
        if (_isClaimed(index)) revert AddressAlreadyClaimed();
        if (merkleProof.length > MAX_PROOF_LENGTH) revert MerkleProofTooLong();

        bytes32 leaf = keccak256(abi.encode(index, account));
        if (!MerkleProof.verify(merkleProof, merkleRoot, leaf)) revert InvalidMerkleProof();

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

    /// @notice Batch claim tokens for multiple addresses using Merkle proofs
    /// @param indexes The array of indexes for the addresses
    /// @param accounts The array of addresses claiming tokens
    /// @param proofs The array of Merkle proofs for the addresses
    /// @return bool True if successful
    function batchClaim(
        uint256[] calldata indexes,
        address[] calldata accounts,
        bytes32[][] calldata proofs
    ) external nonReentrant {
        if (paused) revert ContractPaused();
        if (indexes.length != accounts.length) revert ArrayLengthMismatch();
        if (indexes.length != proofs.length) revert ArrayLengthMismatch();
        if (indexes.length == 0 || indexes.length > 50) revert InvalidBatchSize();
        if (airdropEnded) revert AirdropAlreadyEnded();

        // Combined validation and processing to prevent front-running
        // Process each claim immediately after validation to avoid window of vulnerability
        for (uint256 i = 0; i < indexes.length; ) {
            address account = accounts[i];
            uint256 index = indexes[i];
            bytes32[] calldata proof = proofs[i];
            
            if (account == address(0)) revert InvalidAccountAddress();
            if (_isClaimed(index)) revert AddressAlreadyClaimed();
            if (proof.length > MAX_PROOF_LENGTH) revert MerkleProofTooLong();
            
            // Verify Merkle proof
            bytes32 leaf = keccak256(abi.encode(index, account));
            if (!MerkleProof.verify(proof, merkleRoot, leaf)) revert InvalidMerkleProof();
            
            // Immediately mark as claimed and mint to prevent front-running
            _setClaimed(index);
            _mint(account, claimAmount);
            emit Claimed(index, account, claimAmount);
            
            unchecked {
                ++i;
            }
        }
    }

    /// @notice End the airdrop, preventing further claims
    /// @dev Only callable by the owner
    function endAirdrop() external onlyOwner {
        if (airdropEnded) revert AirdropAlreadyEnded();
        airdropEnded = true;
        emit AirdropEnded(msg.sender, block.timestamp);
    }

    /// @notice Pause the airdrop, preventing all claims and transfers
    /// @dev Only callable by the owner
    function pause() external onlyOwner {
        if (paused) revert ContractPaused();
        paused = true;
        emit Paused(msg.sender, block.timestamp);
    }

    /// @notice Unpause the airdrop, allowing claims and transfers to resume
    /// @dev Only callable by the owner
    function unpause() external onlyOwner {
        if (!paused) revert ContractPaused();
        paused = false;
        emit Unpaused(msg.sender, block.timestamp);
    }

    /// @notice Recover ERC20 tokens accidentally sent to the contract
    /// @param token The token address to recover
    /// @param to The address to send recovered tokens to
    /// @param amount The amount to recover
    function recoverTokens(address token, address to, uint256 amount) external onlyOwner nonReentrant {
        if (token == address(0)) revert InvalidAccountAddress();
        if (to == address(0)) revert CannotTransferToZeroAddress();
        if (token == address(this)) revert CannotRecoverOwnToken();
        if (IERC20(token).balanceOf(address(this)) < amount) revert InsufficientTokenBalance();
        
        bool success = IERC20(token).transfer(to, amount);
        if (!success) revert TokenTransferFailed();
        
        emit TokensRecovered(token, to, amount);
    }

    /// @notice Recover ETH accidentally sent to the contract
    /// @param to The address to send recovered ETH to
    /// @param amount The amount to recover
    function recoverETH(address payable to, uint256 amount) external onlyOwner nonReentrant {
        if (to == address(0)) revert CannotTransferToZeroAddress();
        if (address(this).balance < amount) revert InsufficientETHBalance();
        
        (bool success, ) = to.call{value: amount, gas: 2300}("");
        if (!success) revert ETHTransferFailed();
        
        emit ETHRecovered(to, amount);
    }

    // --- Ownership ---
    /// @notice Initiate ownership transfer to a new owner
    /// @param newOwner The address to transfer ownership to
    /// @dev The new owner must call acceptOwnership to complete the transfer
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert InvalidAccountAddress();
        if (newOwner == owner) revert AlreadyOwner();
        if (pendingOwner != address(0)) revert OwnershipTransferAlreadyPending();
        
        pendingOwner = newOwner;
        emit OwnershipTransferInitiated(owner, newOwner);
    }

    /// @notice Accept pending ownership transfer
    /// @dev Only callable by the pending owner
    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert CallerIsNotPendingOwner();
        
        address previousOwner = owner;
        owner = msg.sender;
        pendingOwner = address(0);
        emit OwnershipTransferred(previousOwner, msg.sender);
    }

    /// @notice Cancel a pending ownership transfer
    /// @dev Only callable by the owner
    function cancelOwnershipTransfer() external onlyOwner {
        if (pendingOwner == address(0)) revert NoPendingTransfer();
        
        pendingOwner = address(0);
        emit OwnershipTransferInitiated(owner, address(0));
    }

    // --- Internal ERC20 helpers ---
    function _transfer(address from, address to, uint256 value) internal nonReentrant {
        if (to == address(0)) revert CannotTransferToZeroAddress();
        uint256 fromBal = _balances[from];
        if (fromBal < value) revert InsufficientBalance();
        
        uint256 newFromBalance = fromBal - value;
        uint256 newToBalance = _balances[to] + value;
        _balances[from] = newFromBalance;
        _balances[to] = newToBalance;
        emit Transfer(from, to, value);
    }

    function _approve(address owner, address spender, uint256 value) internal {
        if (spender == address(0)) revert CannotTransferToZeroAddress();
        _allowances[owner][spender] = value;
        emit Approval(owner, spender, value);
    }

    function _mint(address to, uint256 value) internal {
        if (to == address(0)) revert CannotTransferToZeroAddress();
        if (_totalSupply > maxSupply - value) revert ExceedsMaxSupply();
        
        uint256 newTotalSupply = _totalSupply + value;
        uint256 newBalance = _balances[to] + value;
        _totalSupply = newTotalSupply;
        _balances[to] = newBalance;
        emit Transfer(address(0), to, value);
    }

    // --- Claim bitmap helpers ---
    /// @notice Check if an index has been claimed using bit manipulation
    /// @dev Each uint256 word stores 256 bits, representing claim status for 256 addresses
    ///      bitIndex = index % 256, wordIndex = index / 256
    /// @param index The leaf index in the Merkle tree
    /// @return bool True if the index has been claimed
    function _isClaimed(uint256 index) internal view returns (bool) {
        assembly {
            // Calculate word index (each word holds 256 bits = 2^8)
            let wordIndex := shr(8, index)
            // Calculate bit index within the word
            let bitIndex := and(0xff, index)
            // Get the word containing the bit from storage
            let word := sload(wordIndex)
            // Create mask for the specific bit and check if set
            let mask := shl(bitIndex, 1)
            // Return true if bit is set, false otherwise
            mstore(0, iszero(and(word, mask)))
            return(0, 32)
        }
    }

    /// @notice Mark an index as claimed using bit manipulation
    /// @dev Efficiently sets a single bit in the bitmap without affecting other bits
    ///      Uses bitwise OR with a shifted bit mask
    /// @param index The leaf index in the Merkle tree to mark as claimed
    function _setClaimed(uint256 index) internal {
        assembly {
            // Calculate word index (each word holds 256 bits = 2^8)
            let wordIndex := shr(8, index)
            // Calculate bit index within the word
            let bitIndex := and(0xff, index)
            // Create mask for the specific bit
            let mask := shl(bitIndex, 1)
            // Set the bit using bitwise OR with the mask
            sload(wordIndex)
            or(mask, mload(0))
            sstore(wordIndex, mload(0))
        }
    }
}

/// @title MerkleProof
/// @notice Minimal Merkle proof verification library (sorted pair hashing)
/// @dev Uses sorted pair hashing: keccak256(abi.encodePacked(min(a,b), max(a,b)))
///      This approach ensures consistent tree construction regardless of insertion order
library MerkleProof {
    /// @notice Verify a Merkle proof against a root hash
    /// @param proof The array of sibling hashes forming the proof path from leaf to root
    /// @param root The Merkle root hash to verify against
    /// @param leaf The leaf hash (keccak256(abi.encode(index, address)))
    /// @return bool True if the proof is valid
    function verify(bytes32[] calldata proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        return processProof(proof, leaf) == root;
    }

    /// @notice Process a Merkle proof by recursively hashing leaf with each proof element
    /// @param proof The array of sibling hashes forming the proof path
    /// @param leaf The leaf hash to start from
    /// @return bytes32 The computed root hash from the proof
    /// @dev Iteratively combines the current hash with each proof element
    ///      Uses unchecked increment for gas optimization in loops
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
    /// @return bytes32 keccak256 of sorted pair (min, max)
    /// @dev Ensures deterministic tree construction by always sorting the pair
    ///      This prevents different tree structures for the same set of leaves
    function _hashPair(bytes32 a, bytes32 b) private pure returns (bytes32) {
        return a < b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }
}


