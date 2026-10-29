// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * BASELINE contract (Contribution C1 reference point).
 * Re-implements the design described in Nandanwar & Katarya (The Computer Journal, 2025):
 *  - hospital authority registers hospitals, doctors, patients, IoT devices with credentials
 *  - certificate struct matches the paper's NIZKPProver Certificate
 *    (uniqueID, encryptedData, signature, commitment = keccak256(id, data, sig))
 *  - audit trail is kept on-chain.
 * It is deliberately written in the straightforward, storage-heavy style (string roles,
 * dynamic arrays, linear search, audit log in storage). The optimized version
 * (HealthcareOptimized.sol, Day 2) is compared against it under identical compiler settings.
 * NOTE: the paper keys certificates by msg.sender (one per issuer); here they are keyed by
 * uniqueID so that the baseline is functionally usable. Struct fields are unchanged.
 */
contract HealthcareBaseline {
    struct Entity {
        address addr;
        string role;          // "hospital" | "doctor" | "patient" | "device"
        string name;
        bytes32 credentialHash;
        bool registered;
        uint256 registeredAt;
    }

    struct Certificate {
        bytes32 uniqueID;
        address patient;
        address issuer;
        bytes encryptedData;
        bytes signature;
        bytes32 commitment;
        uint256 issuedAt;
        bool valid;
    }

    struct AuditEntry {
        address actor;
        string action;
        bytes32 ref;
        uint256 timestamp;
    }

    address public authority;
    mapping(address => Entity) public entities;
    address[] public entityList;
    mapping(bytes32 => Certificate) public certificates;
    bytes32[] public certificateIds;
    mapping(address => address[]) public accessList; // patient => authorized addresses
    AuditEntry[] public auditLog;

    modifier onlyAuthority() {
        require(msg.sender == authority, "not authority");
        _;
    }

    constructor() {
        authority = msg.sender;
    }

    function _isRole(address a, string memory role) internal view returns (bool) {
        return entities[a].registered &&
            keccak256(bytes(entities[a].role)) == keccak256(bytes(role));
    }

    function _log(string memory action, bytes32 ref) internal {
        auditLog.push(AuditEntry(msg.sender, action, ref, block.timestamp));
    }

    function registerEntity(
        address addr,
        string calldata role,
        string calldata name,
        bytes32 credentialHash
    ) external onlyAuthority {
        require(!entities[addr].registered, "already registered");
        entities[addr] = Entity(addr, role, name, credentialHash, true, block.timestamp);
        entityList.push(addr);
        _log("register", bytes32(uint256(uint160(addr))));
    }

    function issueCertificate(
        address patient,
        bytes32 uniqueID,
        bytes calldata encryptedData,
        bytes calldata signature
    ) external {
        require(_isRole(msg.sender, "hospital"), "issuer not hospital");
        require(_isRole(patient, "patient"), "patient not registered");
        require(certificates[uniqueID].issuedAt == 0, "id exists");
        bytes32 commitment = keccak256(abi.encodePacked(uniqueID, encryptedData, signature));
        certificates[uniqueID] = Certificate(
            uniqueID, patient, msg.sender, encryptedData, signature,
            commitment, block.timestamp, true
        );
        certificateIds.push(uniqueID);
        _log("issue", uniqueID);
    }

    function grantAccess(address grantee) external {
        require(_isRole(msg.sender, "patient"), "not patient");
        require(entities[grantee].registered, "grantee not registered");
        address[] storage list = accessList[msg.sender];
        for (uint256 i = 0; i < list.length; i++) {
            require(list[i] != grantee, "already granted");
        }
        list.push(grantee);
        _log("grant", bytes32(uint256(uint160(grantee))));
    }

    function revokeAccess(address grantee) external {
        address[] storage list = accessList[msg.sender];
        for (uint256 i = 0; i < list.length; i++) {
            if (list[i] == grantee) {
                list[i] = list[list.length - 1];
                list.pop();
                _log("revoke", bytes32(uint256(uint160(grantee))));
                return;
            }
        }
        revert("not granted");
    }

    function hasAccess(address patient, address who) public view returns (bool) {
        address[] storage list = accessList[patient];
        for (uint256 i = 0; i < list.length; i++) {
            if (list[i] == who) return true;
        }
        return false;
    }

    /// Access request that is recorded in the (storage-based) audit log.
    function requestAccess(address patient, bytes32 certId) external returns (bytes memory) {
        require(hasAccess(patient, msg.sender), "no access");
        Certificate storage c = certificates[certId];
        require(c.valid && c.patient == patient, "bad certificate");
        _log("access", certId);
        return c.encryptedData;
    }

    function verifyCertificate(bytes32 uniqueID) external view returns (bool) {
        Certificate storage c = certificates[uniqueID];
        if (!c.valid) return false;
        return c.commitment == keccak256(abi.encodePacked(c.uniqueID, c.encryptedData, c.signature));
    }

    function auditLength() external view returns (uint256) {
        return auditLog.length;
    }
}
