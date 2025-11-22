// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title MerkleAirdropVerifier
/// @notice Verifies inclusion in a fixed Merkle root using ordered (positional) proofs.
/// @dev Leaves are keccak256(address) where the address is the 20-byte value (no 0x prefix).
contract MerkleAirdropVerifier {
    // Merkle root for the whitelist tree.
    bytes32 public constant MERKLE_ROOT =
        0x6696ff85a5c3fb74870f82f67613691a6cde032e373bd4d7d10d97cbf93a3c9d;

    /// @notice Check if `account` is included in the Merkle root using an ordered proof.
    /// @param account The Ethereum address to verify.
    /// @param proof Sibling hashes from leaf to root.
    /// @param siblingLeft For each proof element, true if the sibling is on the left of the current hash.
    function isEligible(
        address account,
        bytes32[] calldata proof,
        bool[] calldata siblingLeft
    ) external pure returns (bool) {
        return verifyProof(leafOf(account), proof, siblingLeft, MERKLE_ROOT);
    }

    /// @notice Verify a leaf against a root with positional Merkle proof.
    /// @param leaf Leaf hash.
    /// @param proof Sibling hashes from leaf to root.
    /// @param siblingLeft For each proof element, true if the sibling is on the left of the current hash.
    /// @param root Root to verify against.
    function verifyProof(
        bytes32 leaf,
        bytes32[] calldata proof,
        bool[] calldata siblingLeft,
        bytes32 root
    ) public pure returns (bool) {
        if (proof.length != siblingLeft.length) revert InvalidProof();
        bytes32 computed = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            computed = siblingLeft[i]
                ? keccak256(bytes.concat(proof[i], computed))
                : keccak256(bytes.concat(computed, proof[i]));
        }
        return computed == root;
    }

    /// @notice Leaf hashing function: keccak256(raw 20-byte address).
    function leafOf(address account) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(account));
    }

    error InvalidProof();
}
