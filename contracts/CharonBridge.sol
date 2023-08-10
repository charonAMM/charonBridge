//SPDX-License-Identifier: Unlicense
pragma solidity 0.8.17;

import "./MerkleTreeWithHistory.sol";
import "./MintableToken.sol";
import "./interfaces/IOracle.sol";
import "./interfaces/IERC20.sol";
import "./interfaces/IVerifier.sol";


contract CharonBridge is MerkleTreeWithHistory, Token{
    /*storage*/
    struct PartnerContract{
      uint256 chainID;//EVM chain ID
      address contractAddress;//contract address of partner contract on given chain
    }

    struct ExtData {
      address recipient;//party recieving tokens
      int256 extAmount;//amount being sent
      uint256 fee;//fee given to relayer
      uint256 rebate;//amount taken from relayer and given to recipient
      bytes encryptedOutput1;//encrypted UTXO output of txn
      bytes encryptedOutput2;//other encrypted UTXO of txn (must spend all in UTXO design)
    }

    struct Commitment{
      ExtData extData;
      Proof proof;
    }

    struct Proof {
      bytes proof;//proof generated by groth16.fullProve()
      bytes32 root;//root of the merkleTree that contains your commmitment
      uint256 extDataHash;//hash of extData (to prevent relayer tampering)
      uint256 publicAmount;//amount you expect out (extAmount - fee)
      bytes32[] inputNullifiers;//nullifiers of input UTXOs (hash of amount, keypair, blinding, index, etc.)
      bytes32[2] outputCommitments;//hash of amount,keypair, bindings of output UTXOs
    }

    Commitment[] depositCommitments;//all commitments deposited by tellor in an array.  depositID is the position in array
    IVerifier public immutable verifier2; //implementation/address of the two input veriifier contract
    IVerifier public immutable verifier16;//implementation/address of the sixteen input veriifier contract
    PartnerContract[] partnerContracts;//list of connected contracts for this deployment
    address[] oracles;//address of the oracle to use for the system
    bool private _lock;//to prevent reentracy
    uint256 public immutable chainID; //chainID of this charon instance
    mapping(bytes32 => bool) nullifierHashes;//zk proof hashes to tell whether someone withdrew
    mapping(bytes32 => uint256) depositIdByCommitmentHash;//gives you a deposit ID (used by tellor) given a commitment
    mapping(address => uint256) public depositAmountByToken;
    mapping(address => address) public mintChainTokenAddy;
    bool public isMintChain;

    //events
    event DepositToOtherChain(address _token, address _sender, uint256 _depositId, int256 _amount);
    event NewCommitment(bytes32 _commitment, uint256 _index, bytes _encryptedOutput, bool _isDeposit);
    event NewNullifier(bytes32 _nullifier);
    event OracleDeposit(uint256 _oracleIndex,bytes _inputData);

    //functions
    /**
     * @dev constructor to launch charon
     * @param _verifier2 address of the verifier contract
     * @param _verifier16 address of the verifier16 contract
     * @param _hasher address of the hasher contract (mimC precompile)
     * @param _oracles address array of oracle contracts
     * @param _merkleTreeHeight merkleTreeHeight (should match that of circom compile)
     * @param _chainID chainID of this chain
     * @param _name name of pool token
     * @param _symbol of pool token
     * @param _isMintChain bool if chain with minting or depositing
     */
    constructor(address _verifier2,
                address _verifier16,
                address _hasher,
                address[] memory _oracles,
                uint32 _merkleTreeHeight,
                uint256 _chainID,
                string memory _name,
                string memory _symbol,
                bool _isMintChain
                )
              MerkleTreeWithHistory(_merkleTreeHeight, _hasher)
              Token(_name,_symbol){
        verifier2 = IVerifier(_verifier2);
        verifier16 = IVerifier(_verifier16);
        chainID = _chainID;
        oracles = _oracles;
        isMintChain = _isMintChain;
    }
    /**
     * @dev function for user to lock tokens for lp/trade on other chain
     * @param _proofArgs proofArgs of deposit commitment generated by zkproof
     * @param _extData data pertaining to deposit
     * @param _token address of token
     * @return _depositId returns the depositId (position in commitment array)
     */
    function depositToOtherChain(Proof memory _proofArgs,ExtData memory _extData, address _token) external returns(uint256 _depositId){
        require(_extData.extAmount > 0, "amount must be positive");
        require(_lock == false);
        depositCommitments.push(Commitment(_extData,_proofArgs));
        _depositId = depositCommitments.length;
        bytes32 _hashedCommitment = keccak256(abi.encode(_proofArgs.proof,_proofArgs.publicAmount,_proofArgs.root));
        depositIdByCommitmentHash[_hashedCommitment] = _depositId;
        require(IERC20(_token).transferFrom(msg.sender, address(this), uint256(_extData.extAmount)));
        if(isMintChain){
          IERC20(_token).burn(msg.sender,uint256(_extData.extAmount));
        }
        depositAmountByToken[_token] += uint256(_extData.extAmount);
        for(uint256 _i = 0; _i<=oracles.length-1; _i++){
          IOracle(oracles[_i]).sendCommitment(getOracleSubmission(_depositId));
        }
        emit DepositToOtherChain(_token, msg.sender, _depositId, _extData.extAmount);
    }

    /**
     * @dev Starts the system
     * @param _partnerChains list of chainID's in this Charon system
     * @param _partnerAddys list of corresponding addresses of charon contracts on chains in _partnerChains
     */
    function finalize(uint256[] memory _partnerChains,
                      address[] memory _partnerAddys
                     ) 
                      external{
        require(partnerContracts.length == 0);
        require(_partnerChains.length > 0);
        for(uint256 _i; _i < _partnerAddys.length; _i++){
          partnerContracts.push(PartnerContract(_partnerChains[_i],_partnerAddys[_i]));
        } 
    }

  
    /**
     * @dev reads tellor commitments to allow you to withdraw on this chain
     * @param _oracleIndex index of oracle in oracle array
    * @param _inputData depending on the bridge, it might be needed and lets you specify what you're pulling
     */
    function oracleDeposit(uint256 _oracleIndex, bytes memory _inputData) external{
        require(_lock == false);
        Proof memory _proof;
        ExtData memory _extData;
        bytes memory _value;
        address _caller;
        (_value,_caller) = IOracle(oracles[_oracleIndex]).getCommitment(_inputData);
        _proof.inputNullifiers = new bytes32[](2);
        (_proof.inputNullifiers[0], _proof.inputNullifiers[1], _proof.outputCommitments[0], _proof.outputCommitments[1], _proof.proof,_extData.encryptedOutput1, _extData.encryptedOutput2) = abi.decode(_value,(bytes32,bytes32,bytes32,bytes32,bytes,bytes,bytes));
        _transact(_proof, _extData, true);
        emit OracleDeposit(_oracleIndex, _inputData);
    }
  
    /**
      * @dev allows users to send tokens anonymously
      * @param _args proof data for sneding tokens
      * @param _extData external (visible data) to verify proof and pay relayer fee
      */
      function transact(Proof memory _args, ExtData memory _extData, address _token) external payable{
        require(_lock == false);
        _lock = true;
        int256 _publicAmount = _extData.extAmount - int256(_extData.fee);
        if(_publicAmount < 0){
          _publicAmount = int256(FIELD_SIZE - uint256(-_publicAmount));
        } 
        require(_args.publicAmount == uint256(_publicAmount));
        require(isKnownRoot(_args.root), "invalid root");
        require(_verifyProof(_args), "invalid proof");
        require(uint256(_args.extDataHash) == uint256(keccak256(abi.encode(_extData))) % FIELD_SIZE, "incorrect ed hash");
        if (_extData.extAmount < 0){
          if(isMintChain){
            address _addy = mintChainTokenAddy[_token];
            if(_addy == address(0)){
              MintableToken _newToken = new MintableToken(address(this),_token,IERC20(_token).symbol(),IERC20(_token).name());
              mintChainTokenAddy[_token] = address(_newToken);
              _addy = mintChainTokenAddy[_token];
            }
            IERC20(_addy).mint(_extData.recipient, uint256(-_extData.extAmount));
          }
          else{
            IERC20(_token).transfer(_extData.recipient, uint256(-_extData.extAmount));//transfering out of the contract
          }
        }
        _transact(_args, _extData, false);
        if(_extData.fee > 0){
          IERC20(_token).mint(msg.sender,_extData.fee);
          if(_extData.rebate > 0){
            require(_extData.fee > _extData.rebate, "rebate too big");
            //allows a user to get some funds to a blank addy
            payable(_extData.recipient).transfer(_extData.rebate);
          }
        }
        require(msg.value == _extData.rebate, "msg value != rebate");
        _lock = false;
    }
      
    //getters
    /**
     * @dev allows you to find a commitment for a given depositId
     * @param _id deposidId of your commitment
     */
    function getDepositCommitmentsById(uint256 _id) external view returns(Commitment memory){
      return depositCommitments[_id - 1];
    }

    /**
     * @dev allows you to find a depositId for a given commitment
     * @param _commitment the commitment of your deposit
     */
    function getDepositIdByCommitmentHash(bytes32 _commitment) external view returns(uint256){
      return depositIdByCommitmentHash[_commitment];
    }

    /**
     * @dev allows you to get the oracles for the contract
     */
    function getOracles() external view returns(address[] memory){
      return oracles;
    }

    /**
     * @dev returns the data for an oracle submission on another chain given a depositId
     */
    function getOracleSubmission(uint256 _depositId) public view returns(bytes memory){
      Commitment memory _p = depositCommitments[_depositId-1];
      return abi.encode(
        _p.proof.inputNullifiers[0],
        _p.proof.inputNullifiers[1],
        _p.proof.outputCommitments[0],
        _p.proof.outputCommitments[1],
        _p.proof.proof,
        _p.extData.encryptedOutput1,
        _p.extData.encryptedOutput2);
    }

    /**
     * @dev returns the partner contracts in this charon system and their chains
     */
    function getPartnerContracts() external view returns(PartnerContract[] memory){
      return partnerContracts;
    }

    /**
     * @dev allows a user to see if their deposit has been withdrawn
     * @param _nullifierHash hash of nullifier identifying withdrawal
     */
    function isSpent(bytes32 _nullifierHash) external view returns (bool) {
      return nullifierHashes[_nullifierHash];
    }

    //internal
        /**
     * @dev internal logic of secret transfers and chd mints
     * @param _args proof data for sending tokens
     * @param _extData external (visible data) to verify proof and pay relayer fee
     * @param _isDeposit bool if done during oracleDeposit
     */
    function _transact(Proof memory _args, ExtData memory _extData, bool _isDeposit) internal{
      for (uint256 _i = 0; _i < _args.inputNullifiers.length; _i++) {
        require(!nullifierHashes[_args.inputNullifiers[_i]], "Input already spent");
        nullifierHashes[_args.inputNullifiers[_i]] = true;
        emit NewNullifier(_args.inputNullifiers[_i]);
      }
      _insert(_args.outputCommitments[0], _args.outputCommitments[1]);
      emit NewCommitment(_args.outputCommitments[0], nextIndex - 2, _extData.encryptedOutput1, _isDeposit);
      emit NewCommitment(_args.outputCommitments[1], nextIndex - 1, _extData.encryptedOutput2, _isDeposit);
    }

    /**
     * @dev internal fucntion for verifying proof's for secret txns
     * @param _args proof data for seending tokens
     * @return bool of whether proof is verified
     */
    function _verifyProof(Proof memory _args) internal view returns (bool) {
      uint[2] memory _a;
      uint[2][2] memory _b;
      uint[2] memory _c;
      (_a,_b,_c) = abi.decode(_args.proof,(uint[2],uint[2][2],uint[2]));
      if (_args.inputNullifiers.length == 2) {
        return
          verifier2.verifyProof(
            _a,_b,_c,
            [
              uint256(_args.root),
              _args.publicAmount,
              chainID,
              uint256(_args.extDataHash),
              uint256(_args.inputNullifiers[0]),
              uint256(_args.inputNullifiers[1]),
              uint256(_args.outputCommitments[0]),
              uint256(_args.outputCommitments[1])
            ]
          );
      } else if (_args.inputNullifiers.length == 16) {
        return
          verifier16.verifyProof(
            _a,_b,_c,
            [
              uint256(_args.root),
              _args.publicAmount,
              chainID,
              uint256(_args.extDataHash),
              uint256(_args.inputNullifiers[0]),
              uint256(_args.inputNullifiers[1]),
              uint256(_args.inputNullifiers[2]),
              uint256(_args.inputNullifiers[3]),
              uint256(_args.inputNullifiers[4]),
              uint256(_args.inputNullifiers[5]),
              uint256(_args.inputNullifiers[6]),
              uint256(_args.inputNullifiers[7]),
              uint256(_args.inputNullifiers[8]),
              uint256(_args.inputNullifiers[9]),
              uint256(_args.inputNullifiers[10]),
              uint256(_args.inputNullifiers[11]),
              uint256(_args.inputNullifiers[12]),
              uint256(_args.inputNullifiers[13]),
              uint256(_args.inputNullifiers[14]),
              uint256(_args.inputNullifiers[15]),
              uint256(_args.outputCommitments[0]),
              uint256(_args.outputCommitments[1])
            ]
          );
      } else {
        revert("bad input count");
      }
  }
}