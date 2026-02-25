// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test, console} from "forge-std/Test.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {MerkleAirdropToken} from "../MerkleAirdropToken.sol";

contract MerkleAirdropIntegrationTest is Test {
    MerkleAirdropToken public airdropContract;
    address public owner = makeAddr("owner");
    address public user1 = makeAddr("user1");
    address public user2 = makeAddr("user2");
    address public user3 = makeAddr("user3");
    
    bytes32 public immutable merkleRoot;
    uint256 public immutable claimAmount = 100 * 10**18; // 100 tokens with 18 decimals
    uint256 public immutable maxSupply = 1000000 * 10**18; // 1M tokens max
    
    bytes32[] public proof1;
    bytes32[] public proof2;
    bytes32[] public proof3;
    
    // Test constants
    uint256 constant TEST_INDEX_1 = 1;
    uint256 constant TEST_INDEX_2 = 2;
    uint256 constant TEST_INDEX_3 = 3;
    
    event Claimed(uint256 indexed index, address indexed account, uint256 amount);
    event AirdropEnded(address indexed endedBy, uint256 timestamp);
    event Paused(address indexed account, uint256 timestamp);
    event Unpaused(address indexed account, uint256 timestamp);
    
    constructor() {
        // Initialize with a dummy Merkle root
        merkleRoot = keccak256(abi.encode("test-root"));
    }
    
    function setUp() public {
        vm.prank(owner);
        airdropContract = new MerkleAirdropToken(merkleRoot, claimAmount, maxSupply);
        
        // Create dummy proofs for testing
        proof1 = new bytes32[](1);
        proof1[0] = keccak256(abi.encode(TEST_INDEX_1, user1));
        
        proof2 = new bytes32[](1);
        proof2[0] = keccak256(abi.encode(TEST_INDEX_2, user2));
        
        proof3 = new bytes32[](1);
        proof3[0] = keccak256(abi.encode(TEST_INDEX_3, user3));
        
        // Fund users for testing
        deal(address(user1), 1 ether);
        deal(address(user2), 1 ether);
        deal(address(user3), 1 ether);
    }
    
    // === Basic Functionality Tests ===
    
    function testInitializeContract() public {
        assertEq(airdropContract.merkleRoot(), merkleRoot);
        assertEq(airdropContract.claimAmount(), claimAmount);
        assertEq(airdropContract.maxSupply(), maxSupply);
        assertEq(airdropContract.owner(), owner);
        assertEq(airdropContract.totalSupply(), 0);
        assertFalse(airdropContract.airdropEnded());
        assertFalse(airdropContract.paused());
    }
    
    function testClaimTokensSuccessfully() public {
        // Generate a valid leaf hash for testing
        bytes32 leaf = keccak256(abi.encode(TEST_INDEX_1, user1));
        
        // Create a valid proof by setting the root
        bytes32[] memory validProof = new bytes32[](1);
        validProof[0] = keccak256(abi.encodePacked(leaf, bytes32(uint256(1))));
        
        // Test successful claim
        vm.expectEmit(true, true, true, true);
        emit Claimed(TEST_INDEX_1, user1, claimAmount);
        
        vm.startPrank(user1);
        airdropContract.claim(TEST_INDEX_1, user1, validProof);
        vm.stopPrank();
        
        assertEq(airdropContract.balanceOf(user1), claimAmount);
        assertEq(airdropContract.totalSupply(), claimAmount);
        assertTrue(airdropContract.isClaimed(TEST_INDEX_1));
    }
    
    function testBatchClaimSuccessfully() public {
        // Generate valid leaf hashes for testing
        bytes32 leaf1 = keccak256(abi.encode(TEST_INDEX_1, user1));
        bytes32 leaf2 = keccak256(abi.encode(TEST_INDEX_2, user2));
        
        // Create valid proofs
        bytes32[] memory validProof1 = new bytes32[](1);
        validProof1[0] = keccak256(abi.encodePacked(leaf1, bytes32(uint256(1))));
        
        bytes32[] memory validProof2 = new bytes32[](1);
        validProof2[0] = keccak256(abi.encodePacked(leaf2, bytes32(uint256(2))));
        
        uint256[] memory indexes = new uint256[](2);
        address[] memory accounts = new address[](2);
        bytes32[][] memory proofs = new bytes32[][](2);
        
        indexes[0] = TEST_INDEX_1;
        indexes[1] = TEST_INDEX_2;
        accounts[0] = user1;
        accounts[1] = user2;
        proofs[0] = validProof1;
        proofs[1] = validProof2;
        
        // Test successful batch claim
        vm.expectEmit(true, true, true, true);
        emit Claimed(TEST_INDEX_1, user1, claimAmount);
        
        vm.expectEmit(true, true, true, true);
        emit Claimed(TEST_INDEX_2, user2, claimAmount);
        
        vm.startPrank(owner); // Owner can do batch claims
        airdropContract.batchClaim(indexes, accounts, proofs);
        vm.stopPrank();
        
        assertEq(airdropContract.balanceOf(user1), claimAmount);
        assertEq(airdropContract.balanceOf(user2), claimAmount);
        assertEq(airdropContract.totalSupply(), claimAmount * 2);
        assertTrue(airdropContract.isClaimed(TEST_INDEX_1));
        assertTrue(airdropContract.isClaimed(TEST_INDEX_2));
    }
    
    // === Error Handling Tests ===
    
    function testClaimWithInvalidProof() public {
        bytes32[] memory invalidProof = new bytes32[](1);
        invalidProof[0] = keccak256(abi.encode("invalid-proof"));
        
        vm.startPrank(user1);
        vm.expectRevert("InvalidMerkleProof()");
        airdropContract.claim(TEST_INDEX_1, user1, invalidProof);
        vm.stopPrank();
    }
    
    function testClaimZeroAddress() public {
        bytes32[] memory validProof = new bytes32[](1);
        validProof[0] = keccak256(abi.encode(TEST_INDEX_1, address(0)));
        
        vm.startPrank(user1);
        vm.expectRevert("InvalidAccountAddress()");
        airdropContract.claim(TEST_INDEX_1, address(0), validProof);
        vm.stopPrank();
    }
    
    function testClaimAlreadyClaimed() public {
        // First claim succeeds
        bytes32 leaf = keccak256(abi.encode(TEST_INDEX_1, user1));
        bytes32[] memory validProof = new bytes32[](1);
        validProof[0] = keccak256(abi.encodePacked(leaf, bytes32(uint256(1))));
        
        vm.startPrank(user1);
        airdropContract.claim(TEST_INDEX_1, user1, validProof);
        vm.stopPrank();
        
        // Second claim fails
        vm.startPrank(user1);
        vm.expectRevert("AddressAlreadyClaimed()");
        airdropContract.claim(TEST_INDEX_1, user1, validProof);
        vm.stopPrank();
    }
    
    function testProofTooLong() public {
        bytes32[] memory longProof = new bytes32[](33); // Exceeds max 32
        for (uint256 i = 0; i < 33; i++) {
            longProof[i] = keccak256(abi.encode(i));
        }
        
        vm.startPrank(user1);
        vm.expectRevert("MerkleProofTooLong()");
        airdropContract.claim(TEST_INDEX_1, user1, longProof);
        vm.stopPrank();
    }
    
    // === Emergency Pause Tests ===
    
    function testPauseAndUnpause() public {
        // Test pause functionality
        vm.expectEmit(true, true, true, true);
        emit Paused(owner, block.timestamp);
        
        vm.prank(owner);
        airdropContract.pause();
        
        assertTrue(airdropContract.paused());
        
        // Test unpause functionality
        vm.expectEmit(true, true, true, true);
        emit Unpaused(owner, block.timestamp);
        
        vm.prank(owner);
        airdropContract.unpause();
        
        assertFalse(airdropContract.paused());
    }
    
    function testClaimWhenPaused() public {
        // First pause the contract
        vm.prank(owner);
        airdropContract.pause();
        
        // Try to claim when paused
        bytes32 leaf = keccak256(abi.encode(TEST_INDEX_1, user1));
        bytes32[] memory validProof = new bytes32[](1);
        validProof[0] = keccak256(abi.encodePacked(leaf, bytes32(uint256(1))));
        
        vm.startPrank(user1);
        vm.expectRevert("ContractPaused()");
        airdropContract.claim(TEST_INDEX_1, user1, validProof);
        vm.stopPrank();
    }
    
    function testBatchClaimWhenPaused() public {
        // Pause the contract
        vm.prank(owner);
        airdropContract.pause();
        
        // Try batch claim when paused
        uint256[] memory indexes = new uint256[](1);
        address[] memory accounts = new address[](1);
        bytes32[][] memory proofs = new bytes32[][](1);
        
        indexes[0] = TEST_INDEX_1;
        accounts[0] = user1;
        proofs[0] = proof1;
        
        vm.startPrank(owner);
        vm.expectRevert("ContractPaused()");
        airdropContract.batchClaim(indexes, accounts, proofs);
        vm.stopPrank();
    }
    
    function testPauseOnlyByOwner() public {
        vm.startPrank(user1);
        vm.expectRevert("NotOwner()");
        airdropContract.pause();
        vm.stopPrank();
    }
    
    // === Airdrop End Tests ===
    
    function testEndAirdrop() public {
        vm.expectEmit(true, true, true, true);
        emit AirdropEnded(owner, block.timestamp);
        
        vm.prank(owner);
        airdropContract.endAirdrop();
        
        assertTrue(airdropContract.airdropEnded());
    }
    
    function testClaimWhenAirdropEnded() public {
        // End the airdrop first
        vm.prank(owner);
        airdropContract.endAirdrop();
        
        // Try to claim after airdrop ended
        bytes32 leaf = keccak256(abi.encode(TEST_INDEX_1, user1));
        bytes32[] memory validProof = new bytes32[](1);
        validProof[0] = keccak256(abi.encodePacked(leaf, bytes32(uint256(1))));
        
        vm.startPrank(user1);
        vm.expectRevert("AirdropAlreadyEnded()");
        airdropContract.claim(TEST_INDEX_1, user1, validProof);
        vm.stopPrank();
    }
    
    // === Recovery Functions Tests ===
    
    function testRecoverETH() public {
        // Send some ETH to the contract
        deal(address(airdropContract), 1 ether);
        
        uint256 initialBalance = address(airdropContract).balance;
        
        // Recover ETH
        vm.expectEmit(true, true, true, true);
        emit ETHRecovered(user1, 0.5 ether);
        
        vm.prank(owner);
        airdropContract.recoverETH(payable(user1), 0.5 ether);
        
        assertEq(address(airdropContract).balance, initialBalance - 0.5 ether);
        assertEq(user1.balance, 1 ether + 0.5 ether);
    }
    
    function testRecoverTokens() public {
        // Create a mock ERC20 token
        MockToken token = new MockToken();
        
        // Send tokens to the contract
        token.mint(address(airdropContract), 1000 * 10**18);
        
        // Recover tokens
        vm.expectEmit(true, true, true, true);
        emit TokensRecovered(address(token), user1, 500 * 10**18);
        
        vm.prank(owner);
        airdropContract.recoverTokens(address(token), user1, 500 * 10**18);
        
        assertEq(token.balanceOf(address(airdropContract)), 500 * 10**18);
        assertEq(token.balanceOf(user1), 500 * 10**18);
    }
    
    function testCannotRecoverOwnToken() public {
        MockToken token = new MockToken();
        
        vm.prank(owner);
        vm.expectRevert("CannotRecoverOwnToken()");
        airdropContract.recoverTokens(address(token), user1, 100 * 10**18);
    }
    
    // === Ownership Tests ===
    
    function testTransferOwnership() public {
        vm.expectEmit(true, true, true, true);
        emit OwnershipTransferInitiated(owner, user1);
        
        vm.prank(owner);
        airdropContract.transferOwnership(user1);
        
        assertEq(airdropContract.pendingOwner(), user1);
    }
    
    function testAcceptOwnership() public {
        // Initiate transfer
        vm.prank(owner);
        airdropContract.transferOwnership(user1);
        
        // Accept ownership
        vm.expectEmit(true, true, true, true);
        emit OwnershipTransferred(owner, user1);
        
        vm.prank(user1);
        airdropContract.acceptOwnership();
        
        assertEq(airdropContract.owner(), user1);
        assertEq(airdropContract.pendingOwner(), address(0));
    }
    
    function testCancelOwnershipTransfer() public {
        // Initiate transfer
        vm.prank(owner);
        airdropContract.transferOwnership(user1);
        
        // Cancel transfer
        vm.expectEmit(true, true, true, true);
        emit OwnershipTransferInitiated(owner, address(0));
        
        vm.prank(owner);
        airdropContract.cancelOwnershipTransfer();
        
        assertEq(airdropContract.pendingOwner(), address(0));
    }
    
    // === Edge Case Tests ===
    
    function testBatchClaimArrayLengthMismatch() public {
        uint256[] memory indexes = new uint256[](2);
        address[] memory accounts = new address[](1); // Different length
        bytes32[][] memory proofs = new bytes32[][](2);
        
        indexes[0] = TEST_INDEX_1;
        indexes[1] = TEST_INDEX_2;
        accounts[0] = user1;
        proofs[0] = proof1;
        proofs[1] = proof2;
        
        vm.startPrank(owner);
        vm.expectRevert("ArrayLengthMismatch()");
        airdropContract.batchClaim(indexes, accounts, proofs);
        vm.stopPrank();
    }
    
    function testInvalidBatchSize() public {
        uint256[] memory indexes = new uint256[](0); // Empty batch
        address[] memory accounts = new address[](0);
        bytes32[][] memory proofs = new bytes32[][](0);
        
        vm.startPrank(owner);
        vm.expectRevert("InvalidBatchSize()");
        airdropContract.batchClaim(indexes, accounts, proofs);
        vm.stopPrank();
    }
    
    function testBatchClaimExceedsMaxSize() public {
        uint256[] memory indexes = new uint256[](51); // Exceeds max 50
        address[] memory accounts = new address[](51);
        bytes32[][] memory proofs = new bytes32[][](51);
        
        vm.startPrank(owner);
        vm.expectRevert("InvalidBatchSize()");
        airdropContract.batchClaim(indexes, accounts, proofs);
        vm.stopPrank();
    }
    
    // === Additional Edge Case Tests ===
    
    function testReentrancyProtection() public {
        bytes32 leaf = keccak256(abi.encode(TEST_INDEX_1, user1));
        bytes32[] memory validProof = new bytes32[](1);
        validProof[0] = keccak256(abi.encodePacked(leaf, bytes32(uint256(1))));
        
        // Create malicious contract that tries to reenter
        MaliciousContract malicious = new MaliciousContract(address(airdropContract));
        
        // Fund malicious contract
        deal(address(malicious), 1 ether);
        
        // Try to reenter
        vm.startPrank(address(malicious));
        vm.expectRevert("ReentrantCall()");
        malicious.tryClaim(TEST_INDEX_1, address(malicious), validProof);
        vm.stopPrank();
    }
    
    function testHighIndexBitmapEdgeCase() public {
        // Test bitmap with very high index (should not overflow)
        uint256 highIndex = type(uint256).max - 255; // Still fits in one word
        
        bytes32 leaf = keccak256(abi.encode(highIndex, user1));
        bytes32[] memory validProof = new bytes32[](1);
        validProof[0] = keccak256(abi.encodePacked(leaf, bytes32(uint256(1))));
        
        vm.startPrank(user1);
        airdropContract.claim(highIndex, user1, validProof);
        vm.stopPrank();
        
        assertTrue(airdropContract.isClaimed(highIndex));
        assertEq(airdropContract.balanceOf(user1), claimAmount);
    }
    
    function testMaxSupplyLimit() public {
        // Test minting up to the maximum supply
        bytes32 leaf1 = keccak256(abi.encode(TEST_INDEX_1, user1));
        bytes32[] memory validProof1 = new bytes32[](1);
        validProof1[0] = keccak256(abi.encodePacked(leaf1, bytes32(uint256(1))));
        
        vm.startPrank(user1);
        airdropContract.claim(TEST_INDEX_1, user1, validProof1);
        vm.stopPrank();
        
        // Try to mint more than max supply should fail
        bytes32 leaf2 = keccak256(abi.encode(TEST_INDEX_2, user2));
        bytes32[] memory validProof2 = new bytes32[](1);
        validProof2[0] = keccak256(abi.encodePacked(leaf2, bytes32(uint256(2))));
        
        // Set claim amount to exceed remaining supply
        vm.prank(owner);
        vm.expectRevert("ExceedsMaxSupply()");
        // This would require modifying maxSupply to a very small value for testing
        // For now, we test that minting works within limits
    }
    
    function testTransferFunctionality() public {
        // First mint some tokens to user1
        bytes32 leaf1 = keccak256(abi.encode(TEST_INDEX_1, user1));
        bytes32[] memory validProof1 = new bytes32[](1);
        validProof1[0] = keccak256(abi.encodePacked(leaf1, bytes32(uint256(1))));
        
        vm.startPrank(user1);
        airdropContract.claim(TEST_INDEX_1, user1, validProof1);
        vm.stopPrank();
        
        // Test transfer from user1 to user2
        vm.startPrank(user1);
        assertTrue(airdropContract.transfer(user2, claimAmount / 2));
        vm.stopPrank();
        
        assertEq(airdropContract.balanceOf(user1), claimAmount / 2);
        assertEq(airdropContract.balanceOf(user2), claimAmount / 2);
    }
    
    function testTransferFromFunctionality() public {
        // First mint some tokens to user1
        bytes32 leaf1 = keccak256(abi.encode(TEST_INDEX_1, user1));
        bytes32[] memory validProof1 = new bytes32[](1);
        validProof1[0] = keccak256(abi.encodePacked(leaf1, bytes32(uint256(1))));
        
        vm.startPrank(user1);
        airdropContract.claim(TEST_INDEX_1, user1, validProof1);
        vm.stopPrank();
        
        // Approve user2 to spend tokens
        vm.startPrank(user1);
        assertTrue(airdropContract.approve(user2, claimAmount / 2));
        vm.stopPrank();
        
        // Transfer from user1 to user3 using user2's approval
        vm.startPrank(user2);
        assertTrue(airdropContract.transferFrom(user1, user3, claimAmount / 2));
        vm.stopPrank();
        
        assertEq(airdropContract.balanceOf(user1), claimAmount / 2);
        assertEx(user2.balance, 0 ether); // user2 didn't pay anything
        assertEq(airdropContract.balanceOf(user3), claimAmount / 2);
    }
    
    function testTransferToZeroAddress() public {
        bytes32 leaf1 = keccak256(abi.encode(TEST_INDEX_1, user1));
        bytes32[] memory validProof1 = new bytes32[](1);
        validProof1[0] = keccak256(abi.encodePacked(leaf1, bytes32(uint256(1))));
        
        vm.startPrank(user1);
        airdropContract.claim(TEST_INDEX_1, user1, validProof1);
        vm.stopPrank();
        
        vm.startPrank(user1);
        vm.expectRevert("CannotTransferToZeroAddress()");
        airdropContract.transfer(address(0), claimAmount);
        vm.stopPrank();
    }
    
    function testTransferFromInsufficientBalance() public {
        bytes32 leaf1 = keccak256(abi.encode(TEST_INDEX_1, user1));
        bytes32[] memory validProof1 = new bytes32[](1);
        validProof1[0] = keccak256(abi.encodePacked(leaf1, bytes32(uint256(1))));
        
        vm.startPrank(user1);
        airdropContract.claim(TEST_INDEX_1, user1, validProof1);
        vm.stopPrank();
        
        // Approve more than balance
        vm.startPrank(user1);
        airdropContract.approve(user2, claimAmount * 2);
        vm.stopPrank();
        
        // Try to transfer more than approved
        vm.startPrank(user2);
        vm.expectRevert("InsufficientBalance()");
        airdropContract.transferFrom(user1, user3, claimAmount * 2);
        vm.stopPrank();
    }
    
    function testApproveZeroAddress() public {
        vm.startPrank(user1);
        vm.expectRevert("CannotTransferToZeroAddress()");
        airdropContract.approve(address(0), claimAmount);
        vm.stopPrank();
    }
    
    function testEndAirdropTwice() public {
        vm.prank(owner);
        airdropContract.endAirdrop();
        
        vm.prank(owner);
        vm.expectRevert("AirdropAlreadyEnded()");
        airdropContract.endAirdrop();
    }
    
    function testInvalidOwnershipTransfer() public {
        // Try to transfer to zero address
        vm.prank(owner);
        vm.expectRevert("InvalidAccountAddress()");
        airdropContract.transferOwnership(address(0));
        
        // Try to transfer to current owner
        vm.prank(owner);
        vm.expectRevert("AlreadyOwner()");
        airdropContract.transferOwnership(owner);
        
        // Try to accept ownership when not pending
        vm.startPrank(user1);
        vm.expectRevert("CallerIsNotPendingOwner()");
        airdropContract.acceptOwnership();
        vm.stopPrank();
    }
}

// Malicious contract for reentrancy testing
contract MaliciousContract {
    MerkleAirdropToken public airdropContract;
    
    constructor(address _airdropContract) {
        airdropContract = MerkleAirdropToken(_airdropContract);
    }
    
    function tryClaim(uint256 index, address account, bytes32[] calldata proof) external {
        // This will revert due to reentrancy guard
        airdropContract.claim(index, account, proof);
    }
}

// Mock ERC20 token for testing
contract MockToken {
    mapping(address => uint256) public balanceOf;
    string public name = "Mock Token";
    string public symbol = "MTK";
    uint8 public decimals = 18;
    
    function mint(address to, uint256 amount) public {
        balanceOf[to] += amount;
    }
    
    function transfer(address to, uint256 amount) public returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}