// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ChainProof
 * @author Prachi Goel
 * @notice On-chain credential system for community contribution tracking.
 *         Credentials are soul-bound (non-transferable) and issued only by the admin.
 *         Each credential is permanently tied to the recipient's wallet address.
 */
contract ChainProof {

    // ─────────────────────────────────────────────────────────────────────────
    // STATE VARIABLES
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice The admin is set once at deployment and never changes.
    /// @dev Non-transferability begins here: admin authority itself is immutable.
    address public immutable admin;

    /**
     * @notice Struct representing a single on-chain credential.
     * @param title  Human-readable name of the credential (e.g. "Completed BlockBase")
     * @param level  Difficulty tier: 1 = Basic, 2 = Intermediate, 3 = Advanced
     * @param issuedAt Unix timestamp of when the credential was issued (block.timestamp)
     */
    struct Credential {
        string  title;
        uint256 level;
        uint256 issuedAt;
    }

    /// @notice Stores the list of all credentials issued to each wallet address.
    /// @dev Mapping is address > dynamic array, so a wallet accumulates credentials over time.
    mapping(address => Credential[]) private credentials;

    /**
     * @notice Tracks whether a specific title has already been issued to an address.
     * @dev Used to enforce the duplicate-rejection policy (see issueCredential).
     *      Keyed as: address => keccak256(title) => bool
     */
    mapping(address => mapping(bytes32 => bool)) private credentialExists;

    // ─────────────────────────────────────────────────────────────────────────
    // TRUST SCORE THRESHOLD
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * @notice Minimum trust score required to pass the accessGranted() gate.
     * @dev Set to 10. Rationale: a member with two Intermediate credentials (2×3=6 base
     *      points each after formula) or one Advanced credential (9 base points) plus a
     *      Basic (1 point) would just qualify. This filters out drive-by participants who
     *      only collect a single entry-level badge.
     */
    uint256 public constant ACCESS_THRESHOLD = 10;

    // ─────────────────────────────────────────────────────────────────────────
    // EVENTS
    // ─────────────────────────────────────────────────────────────────────────

    event CredentialIssued(address indexed recipient, string title, uint256 level, uint256 issuedAt);

    // ─────────────────────────────────────────────────────────────────────────
    // MODIFIERS
    // ─────────────────────────────────────────────────────────────────────────

    modifier onlyAdmin() {
        require(msg.sender == admin, "ChainProof: caller is not admin");
        _;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CONSTRUCTOR
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * @notice Deployer becomes the permanent admin.
     * @dev Using `immutable` means the admin address is baked into bytecode —
     *      it physically cannot be updated after deployment.
     */
    constructor() {
        admin = msg.sender;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CREDENTIAL ISSUANCE
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * @notice Issues a new credential to a member wallet.
     * @dev Only the admin may call this. Credentials cannot be transferred because
     *      they are stored directly in a mapping keyed by the recipient address —
     *      there is no transfer or approval function, and no way to move
     *      the data to a different key. This mirrors the ERC-5192 soul-bound pattern.
     *
     * NON-TRANSFERABILITY EXPLANATION:
     *   Credentials live inside `credentials[recipient]`. There is no `transfer()`,
     *   `approve()`, or `safeTransferFrom()` function in this contract. The only
     *   write path is through `issueCredential()`, which is gated to the admin and
     *   writes directly to the intended recipient's slot. Since there is no mechanism
     *   to re-assign or copy a credential to another address, they are structurally
     *   non-transferable. This matters because the entire trust score of a wallet
     *   must reflect that wallet's own history — not borrowed or purchased reputation.
     *
     * DUPLICATE CREDENTIAL HANDLING:
     *   Decision: REJECT duplicates (revert if the same title already exists for this address).
     *   Reasoning: Allowing the same credential twice would inflate the trust score without
     *   reflecting any new contribution. It would open a trivial admin-abuse vector
     *   (issuing the same badge repeatedly to friends). Overwriting would silently erase
     *   a historical timestamp, losing auditability. Rejection is the only option that
     *   preserves both integrity and the append-only audit trail.
     *
     * @param recipient The wallet address to receive the credential.
     * @param title     Name of the credential. Must be non-empty.
     * @param level     Difficulty level: must be 1, 2, or 3.
     */
    function issueCredential(
        address recipient,
        string  calldata title,
        uint256 level
    ) external onlyAdmin {
        require(recipient != address(0), "ChainProof: zero address");
        require(bytes(title).length > 0,  "ChainProof: title cannot be empty");
        require(level >= 1 && level <= 3,  "ChainProof: level must be 1, 2, or 3");

        // Duplicate rejection: compute a hash of the title and check existence.
        bytes32 titleHash = keccak256(bytes(title));
        require(
            !credentialExists[recipient][titleHash],
            "ChainProof: credential with this title already issued to address"
        );

        // Mark title as issued to this address before writing state (checks-effects-interactions).
        credentialExists[recipient][titleHash] = true;

        credentials[recipient].push(Credential({
            title:    title,
            level:    level,
            issuedAt: block.timestamp
        }));

        emit CredentialIssued(recipient, title, level, block.timestamp);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CREDENTIAL LOOKUP
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * @notice Returns the full credential list of any address.
     * @dev `view` function — free to call, readable by anyone (recruiters, DAOs, etc.).
     * @param member The wallet address to look up.
     * @return Array of all Credential structs issued to that address.
     */
    function getCredentials(address member) external view returns (Credential[] memory) {
        return credentials[member];
    }

    /**
     * @notice Returns the number of credentials held by an address.
     */
    function credentialCount(address member) external view returns (uint256) {
        return credentials[member].length;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // TRUST SCORE
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * @notice Computes the trust score for any wallet address.
     *
     * FORMULA:
     *   For each credential i:
     *       points_i = level_i * level_i          (quadratic level weight)
     *   Raw score  = Σ points_i
     *   Bonus      = floor(Raw score / 5)         (5% breadth bonus per 5 raw points)
     *   TrustScore = Raw score + Bonus
     *
     * REASONING:
     *   1. Quadratic level weighting (level²) strongly rewards depth.
     *      Basic(1) = 1pt, Intermediate(2) = 4pts, Advanced(3) = 9pts.
     *      This is not linear — an Advanced credential is worth 9× a Basic, not 3×.
     *      It discourages gaming via volume of low-effort Basic badges.
     *   2. The breadth bonus adds 1 point for every 5 raw points earned,
     *      rewarding members who accumulate multiple credentials (breadth)
     *      without letting it dominate over genuine depth.
     *   3. Together, both the quality of contributions and the quantity
     *      of distinct contributions are recognised, but depth is the
     *      primary driver. A member with three Advanced badges (27pts + 5 bonus = 32)
     *      will always outrank someone with ten Basic badges (10pts + 2 bonus = 12).
     *
     * EXAMPLE:
     *   Elara: 1× Advanced (9) + 2× Intermediate (4+4) = 17 raw → +3 bonus = 20
     *   Magnus: 0 credentials → score = 0  → accessGranted() reverts
     *
     * @param member The wallet address to score.
     * @return score The computed trust score.
     */
    function trustScore(address member) public view returns (uint256 score) {
        Credential[] storage creds = credentials[member];
        uint256 raw = 0;

        for (uint256 i = 0; i < creds.length; i++) {
            uint256 lvl = creds[i].level;
            raw += lvl * lvl; // quadratic: 1→1, 2→4, 3→9
        }

        uint256 bonus = raw / 5; // breadth bonus: 1 point per 5 raw points
        score = raw + bonus;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ACCESS GATE
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * @notice Gated function — returns true only if the caller's trust score
     *         meets or exceeds ACCESS_THRESHOLD (10).
     * @dev Reverts with a descriptive message if the threshold is not met.
     *      The caller's address is used automatically (msg.sender), making
     *      it impossible to check access on behalf of another address.
     * @return bool Always true if the call does not revert.
     */
    function accessGranted() external view returns (bool) {
        uint256 score = trustScore(msg.sender);
        require(
            score >= ACCESS_THRESHOLD,
            string(abi.encodePacked(
                "ChainProof: access denied - trust score ",
                _uintToString(score),
                " is below required threshold of 10"
            ))
        );
        return true;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // INTERNAL UTILITIES
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * @dev Converts a uint256 to its ASCII string representation.
     *      Used for building the revert reason in accessGranted().
     */
    function _uintToString(uint256 value) internal pure returns (string memory) {
        if (value == 0) return "0";
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        return string(buffer);
    }
}