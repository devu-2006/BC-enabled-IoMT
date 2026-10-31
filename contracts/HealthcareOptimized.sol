// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import { SchnorrLib } from "./SchnorrNIZK.sol";

/**
 * OPTIMIZED contract (C1) with consent-based access control (C2).
 * Same functions as HealthcareBaseline, redesigned for gas:
 *  - Role is an enum (not a string); Entity fields are packed into one slot
 *  - audit trail = events (not a storage array)
 *  - no entityList / certificateIds arrays
 *  - encrypted payload lives off-chain (IPFS); only a bytes32 reference + commitment are stored
 *  - access list = mapping with expiry (O(1) grant / revoke / check, no loops)
 *  - custom errors instead of revert strings; immutable authority
 * New (C2): time-bound consent, emergency (break-glass) access, entity suspension by an IDS oracle.
 */
contract HealthcareOptimized {
    enum Role { None, Hospital, Doctor, Patient, Device }

    struct Entity {
        Role role;
        bool active;
        uint48 registeredAt;
        bytes32 credentialHash; // hash of off-chain credential / metadata
    }

    struct Certificate {
        address patient;
        uint48 issuedAt;
        bool valid;
        bytes32 dataRef;     // IPFS content hash of the encrypted record
        bytes32 commitment;  // keccak256(uniqueID, dataRef, sigHash)
    }

    uint48 public constant EMERGENCY_WINDOW = 1 hours;

    address public immutable authority;
    address public oracle; // e.g. the IDS service account allowed to suspend entities

    mapping(address => Entity) public entities;
    mapping(bytes32 => Certificate) public certificates;
    mapping(address => mapping(address => uint48)) public accessExpiry; // patient => grantee => expiry
    mapping(address => bool) public emergencyAllowed;                   // patient policy

    struct ProofKey {
        bytes32 px;     // x-coordinate of the hospital's Schnorr public key
        uint8 parity;   // 0 = even y, 1 = odd y
    }
    mapping(address => ProofKey) public proofKeys;                      // hospital => NIZKP public key

    error NotAuthority();
    error NotAuthorized();
    error AlreadyRegistered();
    error BadInput();
    error NotFound();
    error IdExists();
    error NoAccess();
    error BadCertificate();
    error EmergencyNotAllowed();
    error BadProof();
    error NoProofKey();

    event EntityRegistered(address indexed entity, Role role, bytes32 credentialHash);
    event EntitySuspended(address indexed entity, address indexed by);
    event EntityReactivated(address indexed entity);
    event CertificateIssued(bytes32 indexed uniqueID, address indexed patient, address indexed issuer, bytes32 dataRef, bytes32 commitment);
    event AccessGranted(address indexed patient, address indexed grantee, uint48 expiry);
    event AccessRevoked(address indexed patient, address indexed grantee);
    event AccessUsed(address indexed patient, address indexed requester, bytes32 indexed certId);
    event EmergencyPolicyChanged(address indexed patient, bool allowed);
    event EmergencyAccess(address indexed patient, address indexed doctor, bytes32 reasonHash, uint48 until);
    event ProofKeySet(address indexed hospital, bytes32 px, uint8 parity);

    constructor() {
        authority = msg.sender;
    }

    modifier onlyAuthority() {
        if (msg.sender != authority) revert NotAuthority();
        _;
    }

    function _isActive(address a, Role role) internal view returns (bool) {
        Entity storage e = entities[a];
        return e.active && e.role == role;
    }

    // ---------------------------------------------------------------- registration
    function _register(address addr, Role role, bytes32 credentialHash) internal {
        if (role == Role.None) revert BadInput();
        if (entities[addr].role != Role.None) revert AlreadyRegistered();
        entities[addr] = Entity(role, true, uint48(block.timestamp), credentialHash);
        emit EntityRegistered(addr, role, credentialHash);
    }

    function registerEntity(address addr, Role role, bytes32 credentialHash) external onlyAuthority {
        _register(addr, role, credentialHash);
    }

    function registerEntities(
        address[] calldata addrs,
        Role[] calldata roles,
        bytes32[] calldata hashes
    ) external onlyAuthority {
        if (addrs.length != roles.length || addrs.length != hashes.length) revert BadInput();
        for (uint256 i = 0; i < addrs.length; i++) {
            _register(addrs[i], roles[i], hashes[i]);
        }
    }

    // ---------------------------------------------------------------- IDS hook
    function setOracle(address o) external onlyAuthority {
        oracle = o;
    }

    function suspendEntity(address a) external {
        if (msg.sender != authority && msg.sender != oracle) revert NotAuthorized();
        if (entities[a].role == Role.None) revert NotFound();
        entities[a].active = false;
        emit EntitySuspended(a, msg.sender);
    }

    function reactivateEntity(address a) external onlyAuthority {
        if (entities[a].role == Role.None) revert NotFound();
        entities[a].active = true;
        emit EntityReactivated(a);
    }

    // ---------------------------------------------------------------- certificates
    function issueCertificate(
        address patient,
        bytes32 uniqueID,
        bytes32 dataRef,
        bytes32 sigHash
    ) external {
        if (!_isActive(msg.sender, Role.Hospital)) revert NotAuthorized();
        if (!_isActive(patient, Role.Patient)) revert NotFound();
        if (certificates[uniqueID].issuedAt != 0) revert IdExists();
        bytes32 commitment = keccak256(abi.encodePacked(uniqueID, dataRef, sigHash));
        certificates[uniqueID] = Certificate(patient, uint48(block.timestamp), true, dataRef, commitment);
        emit CertificateIssued(uniqueID, patient, msg.sender, dataRef, commitment);
    }

    function verifyCertificate(bytes32 uniqueID, bytes32 sigHash) external view returns (bool) {
        Certificate storage c = certificates[uniqueID];
        if (!c.valid) return false;
        return c.commitment == keccak256(abi.encodePacked(uniqueID, c.dataRef, sigHash));
    }

    // ---------------------------------------------------------------- NIZKP-gated issuance (C3)
    /// Message a hospital signs to prove it owns its proof key (proof of possession).
    function keyRegistrationMessage(address hospital) public view returns (bytes32) {
        return keccak256(abi.encodePacked("KEYREG", block.chainid, address(this), hospital));
    }

    /// Message bound by the proof when issuing a certificate (chain, contract, issuer, patient, certificate).
    function certificateProofMessage(
        address issuer,
        address patient,
        bytes32 uniqueID,
        bytes32 dataRef,
        bytes32 sigHash
    ) public view returns (bytes32) {
        return keccak256(abi.encodePacked(block.chainid, address(this), issuer, patient, uniqueID, dataRef, sigHash));
    }

    /// A hospital registers its Schnorr public key, proving it knows the secret key.
    function setProofKey(bytes32 px, uint8 parity, bytes32 e, bytes32 s) external {
        if (!_isActive(msg.sender, Role.Hospital)) revert NotAuthorized();
        if (!SchnorrLib.verify(px, parity, keyRegistrationMessage(msg.sender), e, s)) revert BadProof();
        proofKeys[msg.sender] = ProofKey(px, parity);
        emit ProofKeySet(msg.sender, px, parity);
    }

    /// Certificate issuance that additionally requires a valid NIZKP from the issuing hospital.
    function issueCertificateWithProof(
        address patient,
        bytes32 uniqueID,
        bytes32 dataRef,
        bytes32 sigHash,
        bytes32 e,
        bytes32 s
    ) external {
        if (!_isActive(msg.sender, Role.Hospital)) revert NotAuthorized();
        ProofKey memory k = proofKeys[msg.sender];
        if (k.px == bytes32(0)) revert NoProofKey();
        bytes32 message = certificateProofMessage(msg.sender, patient, uniqueID, dataRef, sigHash);
        if (!SchnorrLib.verify(k.px, k.parity, message, e, s)) revert BadProof();
        if (!_isActive(patient, Role.Patient)) revert NotFound();
        if (certificates[uniqueID].issuedAt != 0) revert IdExists();
        bytes32 commitment = keccak256(abi.encodePacked(uniqueID, dataRef, sigHash));
        certificates[uniqueID] = Certificate(patient, uint48(block.timestamp), true, dataRef, commitment);
        emit CertificateIssued(uniqueID, patient, msg.sender, dataRef, commitment);
    }

    // ---------------------------------------------------------------- consent
    /// duration = 0 means no expiry; otherwise access lasts `duration` seconds.
    function grantAccess(address grantee, uint48 duration) external {
        if (!_isActive(msg.sender, Role.Patient)) revert NotAuthorized();
        if (!entities[grantee].active) revert NotFound();
        uint48 expiry = duration == 0 ? type(uint48).max : uint48(block.timestamp) + duration;
        accessExpiry[msg.sender][grantee] = expiry;
        emit AccessGranted(msg.sender, grantee, expiry);
    }

    function revokeAccess(address grantee) external {
        if (accessExpiry[msg.sender][grantee] == 0) revert NoAccess();
        delete accessExpiry[msg.sender][grantee];
        emit AccessRevoked(msg.sender, grantee);
    }

    function hasAccess(address patient, address who) public view returns (bool) {
        return accessExpiry[patient][who] > block.timestamp && entities[who].active;
    }

    function requestAccess(address patient, bytes32 certId) external returns (bytes32) {
        if (!hasAccess(patient, msg.sender)) revert NoAccess();
        Certificate storage c = certificates[certId];
        if (!c.valid || c.patient != patient) revert BadCertificate();
        emit AccessUsed(patient, msg.sender, certId);
        return c.dataRef;
    }

    // ---------------------------------------------------------------- break-glass
    function setEmergencyPolicy(bool allowed) external {
        if (!_isActive(msg.sender, Role.Patient)) revert NotAuthorized();
        emergencyAllowed[msg.sender] = allowed;
        emit EmergencyPolicyChanged(msg.sender, allowed);
    }

    function emergencyAccess(address patient, bytes32 certId, bytes32 reasonHash) external returns (bytes32) {
        if (!_isActive(msg.sender, Role.Doctor)) revert NotAuthorized();
        if (!emergencyAllowed[patient]) revert EmergencyNotAllowed();
        Certificate storage c = certificates[certId];
        if (!c.valid || c.patient != patient) revert BadCertificate();
        uint48 until = uint48(block.timestamp) + EMERGENCY_WINDOW;
        if (accessExpiry[patient][msg.sender] < until) accessExpiry[patient][msg.sender] = until;
        emit EmergencyAccess(patient, msg.sender, reasonHash, until);
        return c.dataRef;
    }
}