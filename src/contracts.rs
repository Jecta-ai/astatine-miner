#![allow(clippy::too_many_arguments)]
alloy_sol_types::sol! {
    interface AstatineMinerRead {
        error WindowExpired();
        error WindowNotExpired();

        struct WorkInfo {
            bool started;
            bool ended;
            uint64 windowId;
            uint64 windowStartTime;
            uint64 windowExpiryTime;
            bytes32 seed;
            bytes32 prevHash;
            uint256 target;
            uint256 rewardPerWindow;
            uint256 remainingAllocation;
            uint32 maxHeaderLength;
            uint256 submissionFee;
        }

        struct CandidateInfo {
            bool exists;
            address miner;
            uint128 nonce;
            bytes32 workHash;
            uint64 submittedAt;
            bytes header;
            uint64 firstValidSolveSecs;
        }

        struct MiningInfo {
            bool started;
            bool ended;
            uint64 windowId;
            uint64 lastRetargetWindowId;
            uint64 emaSolveSecs;
            uint16 halvingIndex;
            uint256 rewardPerWindow;
            uint256 totalDistributed;
            uint256 nextHalvingThreshold;
            uint256 target;
            bytes32 seed;
            bytes32 prevHash;
        }

        function work() external view returns (WorkInfo memory);
        function candidateSummary() external view returns (CandidateInfo memory);
        function miningState() external view returns (MiningInfo memory);
        function miningPaused() external view returns (bool);
        function hasBest() external view returns (bool);
        function astToken() external view returns (address);
        function SUBMISSION_FEE() external view returns (uint256);
        function WORK_DOMAIN_V2() external view returns (bytes32);
        function computeWorkHash(address miner, uint128 nonce, bytes calldata header)
            external
            view
            returns (bytes32);
        function submitSolution(bytes calldata header, uint128 nonce)
            external
            payable
            returns (bool accepted, bytes32 workHash);
        function finalizeWindow() external;

        event CandidateUpdated(
            uint64 indexed windowId,
            address indexed miner,
            bytes32 indexed workHash,
            uint128 nonce,
            uint64 submittedAt,
            uint64 firstValidSolveSecs
        );
        event SubmissionRejected(
            uint64 indexed windowId,
            address indexed miner,
            bytes32 workHash,
            uint8 reason,
            uint256 fee
        );
        event RewardPaid(
            uint64 indexed windowId, address indexed winner, uint256 amount, uint256 totalDistributed
        );
        event WindowFinalized(
            uint64 indexed completedWindowId,
            uint64 nextWindowId,
            address winner,
            bytes32 virtualBlockHash,
            uint256 payout,
            uint256 targetAfter,
            bytes32 seedAfter,
            uint64 emaAfter,
            bool ended
        );
    }

    interface IERC20Read {
        function decimals() external view returns (uint8);
        function balanceOf(address account) external view returns (uint256);
        event Transfer(address indexed from, address indexed to, uint256 value);
    }
}
