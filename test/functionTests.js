const hre = require('hardhat')
const { ethers } = hre
const { expect, assert } = require('chai')
const { utils } = ethers
const web3 = require('web3');
const abiCoder = new ethers.utils.AbiCoder()
const Utxo = require('../src/utxo')
const { prepareTransaction} = require('../src/index')
const { toFixedHex, poseidonHash } = require('../src/utils')
const { Keypair } = require('../src/keypair')
const { abi, bytecode } = require("usingtellor/artifacts/contracts/TellorPlayground.sol/TellorPlayground.json")
const HASH = require("../build/Hasher.json")
const h = require("usingtellor/test/helpers/helpers.js");
const { buildPoseidon } = require("circomlibjs");

async function deploy(contractName, ...args) {
    const Factory = await ethers.getContractFactory(contractName)
    const instance = await Factory.deploy(...args)
    return instance.deployed()
  }

describe("charon tests", function () {
    let accounts;
    let verifier2,verifier16,token,charon,hasher,token2,charon2, mockNative ,mockNative2, cfc,cfc2, tellorBridge, tellorBridge2, e2p, p2e;
    let fee = 0;
    let HEIGHT = 23;
    let builtPoseidon;
    beforeEach(async function () {
        builtPoseidon = await buildPoseidon()
        accounts = await ethers.getSigners();
        verifier2 = await deploy('Verifier2')
        verifier16 = await deploy('Verifier16')
        let Hasher = await ethers.getContractFactory(HASH.abi, HASH.bytecode);
        hasher = await Hasher.deploy();
        await hasher.deployed()
        token = await deploy("MintableToken",accounts[0].address,accounts[0].address,"Dissapearing Space Monkey","DSM")
        await token.mint(accounts[0].address,web3.utils.toWei("1000000"))//1M
        token2 = await deploy("MintableToken",accounts[0].address,accounts[0].address,"Dissapearing Space Monkey2","DSM2")
        await token2.mint(accounts[0].address,web3.utils.toWei("1000000"))//1M
        //deploy tellor
        let TellorOracle = await ethers.getContractFactory(abi, bytecode);
        tellor = await TellorOracle.deploy();
        tellor2 = await TellorOracle.deploy();
        await tellor2.deployed();
        await tellor.deployed();
        tellorBridge = await deploy("TellorBridge", tellor.address)
        tellorBridge2 = await deploy("TellorBridge", tellor2.address)
        charon = await deploy("CharonBridge",verifier2.address,verifier16.address,hasher.address,[tellorBridge.address],HEIGHT,1,"Charon Pool Token","CPT",false)
        charon2 = await deploy("CharonBridge",verifier2.address,verifier16.address,hasher.address,[tellorBridge2.address],HEIGHT,2,"Charon Pool Token2","CPT2",true);
        await tellorBridge.setPartnerInfo(charon2.address, 2);
        await tellorBridge2.setPartnerInfo(charon.address,1);
        await charon.finalize([2],[charon2.address]);
        await charon2.finalize([1],[charon.address]);
    });
    function poseidon(inputs){
      let val = builtPoseidon(inputs)
      return builtPoseidon.F.toString(val)
    }

    function poseidon2(a,b){
      return poseidon([a,b])
    }
    it("generates same poseidon hash", async function () {
        const res = await hasher["poseidon(bytes32[2])"]([toFixedHex(1,32), toFixedHex(1,32)]);
        const res2 = await poseidonHash([toFixedHex(1,32), toFixedHex(1,32)]);
        assert(res - res2 == 0, "should be the same hash");
    }).timeout(500000);
    it("Test Constructor", async function() {
        let _o = await charon.getOracles();
        assert(_o[0] == tellorBridge.address, "oracle  address should be set")
        assert(await charon.levels() == HEIGHT, "merkle Tree height should be set")
        assert(await charon.hasher() == hasher.address, "hasher should be set")
        assert(await charon.verifier2() == verifier2.address, "verifier2 should be set")
        assert(await charon.verifier16() == verifier16.address, "verifier16 should be set")
        assert(await charon.chainID() == 1, "chainID should be correct")
      });
      it("Test depositToOtherChain", async function() {
        let _amount = web3.utils.toWei("10");
        await token.mint(accounts[1].address,web3.utils.toWei("100"))
        const sender = accounts[0]
        const aliceDepositUtxo = new Utxo({ amount: _amount,myHashFunc: poseidon , chainID: 2, tokenAddress:token.address})
        charon = charon.connect(sender)
        let inputData = await prepareTransaction({
          charon,
          tokenAddress: token.address,
          inputs:[],
          outputs: [aliceDepositUtxo],
          account: {
            owner: sender.address,
            publicKey: aliceDepositUtxo.keypair.address(),
          },
          privateChainID: 2,
          myHasherFunc: poseidon,
          myHasherFunc2: poseidon2
        })
        let args = inputData.args
        let extData = inputData.extData
        await h.expectThrow(charon.connect(accounts[1]).depositToOtherChain(args,extData,token.address))
        await token.connect(accounts[1]).approve(charon.address,web3.utils.toWei("100"))
        await charon.connect(accounts[1]).depositToOtherChain(args,extData,token.address)
        let commi = await charon.getDepositCommitmentsById(1);
        assert(commi[1].proof == args.proof, "commitment a should be stored")
        assert(commi[1].publicAmount - args.publicAmount == 0, "commitment publicAmount should be stored")
        assert(commi[1].root == args.root, "commitment root should be stored")
        assert(commi[1].inputNullifiers[0] == args.inputNullifiers[0], "commitment inputNullifiers should be stored")
        assert(commi[1].inputNullifiers[1] == args.inputNullifiers[1], "commitment inputNullifiers should be stored")
        assert(commi[1].outputCommitments[0] == args.outputCommitments[0], "commitment outputCommitments should be stored")
        assert(commi[1].outputCommitments[1] == args.outputCommitments[1], "commitment outputCommitments should be stored")
        assert(commi[1].extDataHash - args.extDataHash == 0, "commitment extDataHash should be stored")
        assert(commi[0].recipient == extData.recipient, "extData should be correct");
        assert(commi[0].extAmount - extData.extAmount == 0, "extDataAmount should be correct");
        assert(commi[0].relayer == extData.relayer, "extData should be correct");
        assert(commi[0].fee - extData.fee == 0, "extData fee should be correct");
        const dataEncoded = await ethers.utils.AbiCoder.prototype.encode(
          ['bytes','uint256','bytes32'],
          [args.proof,args.publicAmount,args.root]
        );
        assert(await charon.getDepositIdByCommitmentHash(h.hash(dataEncoded)) == 1, "reverse commitment mapping should work")
        assert(await charon.depositAmountByToken(token.address) * 1 -(1* web3.utils.toWei("10")) == 0, "depositAmount should go up")
        assert(await token.balanceOf(accounts[1].address) == web3.utils.toWei("90"), "balance should change properly")
      });
      it("Test finalize", async function() {
        let testCharon = await deploy("CharonBridge",verifier2.address,verifier16.address,hasher.address,[tellor2.address],HEIGHT,2,"Charon Pool Token2","CPT2",true);
        await h.expectThrow(testCharon.finalize([],[]));//must have info
        await testCharon.finalize([1],[charon.address]);
        await h.expectThrow(testCharon.finalize([1],[charon.address]))//already finalized
        let pC = await testCharon.getPartnerContracts();
        assert(pC[0][0] == 1, "partner chain should be correct")
        assert(pC[0][1] == charon.address, "partner address should be correct")
      });
    it("Test oracleDeposit", async function() {
        await token.mint(accounts[1].address,web3.utils.toWei("100"))
        let _amount = web3.utils.toWei("10");
        await token.connect(accounts[1]).approve(charon.address,_amount)
        const sender = accounts[0]
        const aliceDepositUtxo = new Utxo({ amount: _amount, myHashFunc:poseidon, chainID: 2, tokenAddress:token.address })
        charon = charon.connect(sender)
        let inputData = await prepareTransaction({
          charon,
          tokenAddress: token.address,
          inputs:[],
          outputs: [aliceDepositUtxo],
          account: {
            owner: sender.address,
            publicKey: aliceDepositUtxo.keypair.address(),
          },
          privateChainID: 2,
          myHasherFunc: poseidon,
          myHasherFunc2: poseidon2
        })
        let args = inputData.args
        let extData = inputData.extData
        await charon.connect(accounts[1]).depositToOtherChain(args,extData,token.address);
        const dataEncoded = await ethers.utils.AbiCoder.prototype.encode(
          ['bytes','uint256','bytes32'],
          [args.proof,args.publicAmount,args.root]
        );
        let depositId = await charon.getDepositIdByCommitmentHash(h.hash(dataEncoded))
        let _query = await getTellorData(tellor2,charon.address,1,depositId);
        let _value = await charon.getOracleSubmission(depositId);
        let _bnum = await ethers.provider.getBlockNumber();
        let _evmCallVal = await ethers.utils.AbiCoder.prototype.encode(
          ['bytes','uint256'],
          [await ethers.utils.AbiCoder.prototype.encode(['bytes'],[_value]),_bnum]
        );
        _encoded = await ethers.utils.AbiCoder.prototype.encode(['uint256'],[depositId]);
        await h.expectThrow(charon2.oracleDeposit([0],_encoded));
        await tellor2.submitValue(_query.queryId, _evmCallVal,_query.nonce, _query.queryData);
        await h.advanceTime(86400)//wait 12 hours
        await charon2.oracleDeposit([0],_encoded);
        await h.expectThrow(charon2.oracleDeposit([0],web3.utils.sha3(_encoded, {encoding: 'hex'})))
        assert(await charon2.isSpent(args.inputNullifiers[0]) == true ,"nullifierHash should be true")
        assert(await charon2.isSpent(args.inputNullifiers[1]) == true ,"nullifierHash should be true")
        });
        it("deposit and transact", async function () {
            await token.mint(accounts[1].address,web3.utils.toWei("100"))
            let _amount = utils.parseEther('10');
            await token.connect(accounts[1]).approve(charon.address,_amount)
            const sender = accounts[0]
            const aliceDepositUtxo = new Utxo({ amount: _amount, myHashFunc: poseidon, chainID: 2, tokenAddress:token.address })
            charon = charon.connect(sender)
            let inputData = await prepareTransaction({
              charon,
              inputs:[],
              tokenAddress: token.address,
              outputs: [aliceDepositUtxo],
              account: {
                owner: sender.address,
                publicKey: aliceDepositUtxo.keypair.address(),
              },
              privateChainID: 2,
              myHasherFunc: poseidon,
              myHasherFunc2: poseidon2
            })
            let args = inputData.args
            let extData = inputData.extData
            await charon.connect(accounts[1]).depositToOtherChain(args,extData,token.address);
            const dataEncoded = await ethers.utils.AbiCoder.prototype.encode(
            ['bytes','uint256','bytes32'],
            [args.proof,args.publicAmount,args.root]
            );
            let depositId = await charon.getDepositIdByCommitmentHash(h.hash(dataEncoded))
            let _query = await getTellorData(tellor2,charon.address,1,depositId);
            let _value = await charon.getOracleSubmission(depositId);
            let _bnum = await ethers.provider.getBlockNumber();
            let _evmCallVal = await ethers.utils.AbiCoder.prototype.encode(
              ['bytes','uint256'],
              [await ethers.utils.AbiCoder.prototype.encode(['bytes'],[_value]),_bnum]
            );
            await tellor2.submitValue(_query.queryId, _evmCallVal,_query.nonce, _query.queryData);
            await h.advanceTime(86400)//wait 12 hours
            _encoded = await ethers.utils.AbiCoder.prototype.encode(['uint256'],[depositId]);
            await charon2.oracleDeposit([0],_encoded);
            // Alice sends some funds to withdraw (ignore bob)
            let bobSendAmount = utils.parseEther('4')
            const bobKeypair = new Keypair({myHashFunc:poseidon}) // contains private and public keys
 // contains private and public keys
            const bobAddress = await bobKeypair.address() // contains only public key
            const bobSendUtxo = new Utxo({ amount: bobSendAmount,myHashFunc: poseidon, keypair: Keypair.fromString(bobAddress,poseidon), chainID: 2, tokenAddress:token.address })
            let aliceChangeUtxo = new Utxo({
                amount: _amount.sub(bobSendAmount),
                myHashFunc: poseidon,
                keypair: aliceDepositUtxo.keypair,
                chainID: 2,
                tokenAddress:token.address
            })
            inputData = await prepareTransaction({
                charon: charon2,
                tokenAddress: token.address,
                inputs:[aliceDepositUtxo],
                outputs: [bobSendUtxo, aliceChangeUtxo],
                privateChainID: 2,
                myHasherFunc: poseidon,
                myHasherFunc2: poseidon2
              })
            args = inputData.args
            extData = inputData.extData
            let badArg1,badExtData,badArg2,badExtData2
            badArg1 = Object.assign({},args);
            badArg1.root = h.hash("badroot")
            badExtData = Object.assign({},extData)
            badExtData.extAmount = '0x00000000055000000000000000000000000000000000000000000000000000000'
            badArg2 = Object.assign({},args);
            badArg2.proof = h.hash("badproof")
            badExtData2 = Object.assign({},extData)
            badExtData2.recipient = accounts[2].address
            await h.expectThrow(charon2.transact(badArg1,extData,token.address))//bad root
            await h.expectThrow(charon2.transact(badArg2,extData,token.address))//bad proof
            await h.expectThrow(charon2.transact(args,badExtData,token.address))//bad public amount
            await h.expectThrow(charon2.transact(args,badExtData2,token.address))// bad extData hash (changed recipient)
            assert(await charon2.isKnownRoot(inputData.args.root));
            await charon2.transact(args,extData,token.address)
                // Bob parses chain to detect incoming funds
            const filter = charon2.filters.NewCommitment()
            const fromBlock = await ethers.provider.getBlock()
            const events = await charon2.queryFilter(filter, fromBlock.number)
            let bobReceiveUtxo
            try {
                bobReceiveUtxo = Utxo.decrypt(bobKeypair, events[0].args._encryptedOutput, events[0].args._index)
            } catch (e) {
            // we try to decrypt another output here because it shuffles outputs before sending to blockchain
                bobReceiveUtxo = Utxo.decrypt(bobKeypair, events[1].args._encryptedOutput, events[1].args._index)
            }
            expect(bobReceiveUtxo.amount).to.be.equal(bobSendAmount)
        })
        it("deposit and withdraw", async function () {
            await token.mint(accounts[1].address,web3.utils.toWei("100"))
            let _amount = utils.parseEther('10');
            await token.connect(accounts[1]).approve(charon.address,_amount)
            const sender = accounts[0]
            const aliceDepositUtxo = new Utxo({ amount: _amount,myHashFunc: poseidon, chainID: 2, tokenAddress:token.address })
            charon = charon.connect(sender)
            let inputData = await prepareTransaction({
              charon,
              tokenAddress: token.address,
              inputs:[],
              outputs: [aliceDepositUtxo],
              account: {
                owner: sender.address,
                publicKey: aliceDepositUtxo.keypair.address(),
              },
              privateChainID: 2,
              myHasherFunc: poseidon,
              myHasherFunc2: poseidon2
            })
            let args = inputData.args
            let extData = inputData.extData
            await charon.connect(accounts[1]).depositToOtherChain(args,extData,token.address);
            const dataEncoded = await ethers.utils.AbiCoder.prototype.encode(
            ['bytes','uint256','bytes32'],
            [args.proof,args.publicAmount,args.root]
            );
            let depositId = await charon.getDepositIdByCommitmentHash(h.hash(dataEncoded))
            let _query = await getTellorData(tellor2,charon.address,1,depositId);
            let _value = await charon.getOracleSubmission(depositId);
            let _bnum = await ethers.provider.getBlockNumber();
            let _evmCallVal = await ethers.utils.AbiCoder.prototype.encode(
              ['bytes','uint256'],
              [await ethers.utils.AbiCoder.prototype.encode(['bytes'],[_value]),_bnum]
            );
            await tellor2.submitValue(_query.queryId, _evmCallVal,_query.nonce, _query.queryData);
            await h.advanceTime(86400)//wait 12 hours
            _encoded = await ethers.utils.AbiCoder.prototype.encode(['uint256'],[depositId]);
            await charon2.oracleDeposit([0],_encoded);
            //alice withdraws
            inputData = await prepareTransaction({
                charon: charon2,
                tokenAddress: token.address,
                inputs: [aliceDepositUtxo],
                outputs: [],
                recipient: accounts[1].address,
                privateChainID: 2,
                myHasherFunc: poseidon,
                myHasherFunc2: poseidon2
            })
            await charon2.transact(inputData.args,inputData.extData,token.address)
        })
        it("gas costs by function", async function () {
            await token.mint(accounts[1].address,web3.utils.toWei("100"))
            let _amount = utils.parseEther('10');
            await token.connect(accounts[1]).approve(charon.address,_amount)
            const sender = accounts[0]
            const aliceDepositUtxo = new Utxo({ amount: _amount, myHashFunc: poseidon, chainID: 2, tokenAddress:token.address })
            charon = charon.connect(sender)
            let inputData = await prepareTransaction({
              charon,
              tokenAddress: token.address,
              inputs:[],
              outputs: [aliceDepositUtxo],
              account: {
                owner: sender.address,
                publicKey: aliceDepositUtxo.keypair.address(),
              },
              privateChainID: 2,
              myHasherFunc: poseidon,
              myHasherFunc2: poseidon2
            })
            let args = inputData.args
            let extData = inputData.extData
            let gas = await charon.connect(accounts[1]).estimateGas.depositToOtherChain(args,extData,token.address);
            console.log('depositToOtherChain', gas - 0)
            await charon.connect(accounts[1]).depositToOtherChain(args,extData,token.address);
            const dataEncoded = await ethers.utils.AbiCoder.prototype.encode(
            ['bytes','uint256','bytes32'],
            [args.proof,args.publicAmount,args.root]
            );
            let depositId = await charon.getDepositIdByCommitmentHash(h.hash(dataEncoded)) 
            let _query = await getTellorData(tellor2,charon.address,1,depositId);
            let _value = await charon.getOracleSubmission(depositId);
            let _bnum = await ethers.provider.getBlockNumber();
            let _evmCallVal = await ethers.utils.AbiCoder.prototype.encode(
              ['bytes','uint256'],
              [await ethers.utils.AbiCoder.prototype.encode(['bytes'],[_value]),_bnum]
            );
            await tellor2.submitValue(_query.queryId, _evmCallVal,_query.nonce, _query.queryData);
            await h.advanceTime(86400)//wait 12 hours
            _encoded = await ethers.utils.AbiCoder.prototype.encode(['uint256'],[depositId]);
            gas =  await charon2.estimateGas.oracleDeposit([0],_encoded);
            console.log('oracleDeposit', gas - 0)
            await charon2.oracleDeposit([0],_encoded);
            // Alice sends some funds to withdraw (ignore bob)
            let bobSendAmount = utils.parseEther('4')
            const bobKeypair = new Keypair({myHashFunc:poseidon}) // contains private and public keys
 // contains private and public keys
            const bobAddress = await bobKeypair.address() // contains only public key
            const bobSendUtxo = new Utxo({ amount: bobSendAmount,myHashFunc: poseidon, keypair: bobKeypair, chainID: 2, tokenAddress: token.address })
            let aliceChangeUtxo = new Utxo({
                amount: _amount.sub(bobSendAmount),
                myHashFunc: poseidon,
                keypair: aliceDepositUtxo.keypair,
                chainID: 2,
                tokenAddress: token.address
            })
            inputData = await prepareTransaction({
                charon: charon2,
                tokenAddress: token.address,
                inputs:[aliceDepositUtxo],
                outputs: [bobSendUtxo, aliceChangeUtxo],
                privateChainID: 2,
                myHasherFunc: poseidon,
                myHasherFunc2: poseidon2
              })
            args = inputData.args
            extData = inputData.extData
            gas = await charon2.estimateGas.transact(args,extData,token.address)
            console.log('transact (2)', gas- 0)
            await charon2.transact(args,extData,token.address)
            //add transact16
            const bobSendUtxo2 = new Utxo({ amount: bobSendAmount,myHashFunc: poseidon, keypair: bobKeypair , chainID: 2, tokenAddress: token.address})
            let aliceChangeUtxo2 = new Utxo({
                amount: _amount.sub(bobSendAmount),
                myHashFunc: poseidon,
                keypair: aliceChangeUtxo.keypair,
                chainID: 2,
                tokenAddress: token.address
            })
            inputData = await prepareTransaction({
                charon: charon2,
                tokenAddress: token.address,
                inputs:[aliceChangeUtxo],
                outputs: [bobSendUtxo2, aliceChangeUtxo2],
                privateChainID: 2,
                myHasherFunc: poseidon,
                myHasherFunc2: poseidon2
              })
            args = inputData.args
            extData = inputData.extData
            await charon2.transact(args,extData,token.address)
            //second w/ more
            let charlieSendAmount = utils.parseEther('7')
            const charlieKeypair = new Keypair({myHashFunc:poseidon}) // contains private and public keys
            // contains private and public keys
                       const charlieAddress = await charlieKeypair.address() // contains only public key
                       const charlieSendUtxo = new Utxo({ amount: charlieSendAmount,myHashFunc: poseidon, keypair: Keypair.fromString(charlieAddress,poseidon),chainID: 2, tokenAddress: token.address })
                       let bobChangeUtxo = new Utxo({
                           amount: utils.parseEther('1'),
                           myHashFunc: poseidon,
                           keypair: bobSendUtxo.keypair,
                           chainID: 2,
                           tokenAddress: token.address
                       })
                       inputData = await prepareTransaction({
                           charon: charon2,
                           tokenAddress: token.address,
                           inputs:[bobSendUtxo, bobSendUtxo2],
                           outputs: [bobChangeUtxo,charlieSendUtxo],
                           privateChainID: 2,
                           myHasherFunc: poseidon,
                           myHasherFunc2: poseidon2
                         })
                       args = inputData.args
                       extData = inputData.extData
                       gas = await charon2.estimateGas.transact(args,extData,token.address)
                       console.log('transact (16)', gas- 0)
                       await charon2.transact(args,extData,token.address)
        })
        it("Test getDepositCommitmentsById()", async function() {
          await token.mint(accounts[4].address,web3.utils.toWei("100"))
          let _amount = utils.parseEther('10');
          const sender = accounts[4]
          const aliceDepositUtxo = new Utxo({ amount: _amount,myHashFunc: poseidon , chainID: 2,tokenAddress: token.address})
          charon = charon.connect(sender)
          let inputData = await prepareTransaction({
            charon,
            tokenAddress: token.address,
            inputs:[],
            outputs: [aliceDepositUtxo],
            account: {
              owner: sender.address,
              publicKey: aliceDepositUtxo.keypair.address(),
            },
            privateChainID: 2,
            myHasherFunc: poseidon,
            myHasherFunc2: poseidon2
          })
          let args = inputData.args
          let extData = inputData.extData
          await h.expectThrow(charon.connect(accounts[1]).depositToOtherChain(args,extData,token.address))
          await h.expectThrow(charon.connect(accounts[1]).depositToOtherChain(args,extData,token.address))
          await token.connect(accounts[4]).approve(charon.address,_amount)
          await charon.connect(accounts[4]).depositToOtherChain(args,extData,token.address);
          let commi = await charon.getDepositCommitmentsById(1);
          assert(commi[1].proof == args.proof, "commitment a should be stored")
          assert(commi[1].publicAmount - args.publicAmount == 0, "commitment publicAmount should be stored")
          assert(commi[1].root == args.root, "commitment root should be stored")
          assert(commi[1].inputNullifiers[0] == args.inputNullifiers[0], "commitment inputNullifiers should be stored")
          assert(commi[1].inputNullifiers[1] == args.inputNullifiers[1], "commitment inputNullifiers should be stored")
          assert(commi[1].outputCommitments[0] == args.outputCommitments[0], "commitment outputCommitments should be stored")
          assert(commi[1].outputCommitments[1] == args.outputCommitments[1], "commitment outputCommitments should be stored")
          assert(commi[1].extDataHash - args.extDataHash == 0, "commitment extDataHash should be stored")
          assert(commi[0].recipient == extData.recipient, "extData should be correct");
          assert(commi[0].extAmount - extData.extAmount == 0, "extDataAmount should be correct");
          assert(commi[0].relayer == extData.relayer, "extData should be correct");
          assert(commi[0].fee - extData.fee == 0, "extData fee should be correct");
        });
        it("Test getDepositIdByCommitmentHash()", async function() {
          const sender = accounts[0]
          await token.mint(accounts[1].address,web3.utils.toWei("100"))
          let _amount = utils.parseEther('10');
          let aliceDepositUtxo = new Utxo({ amount: _amount,myHashFunc: poseidon, chainID: 2, tokenAddress: token.address })
          charon = charon.connect(sender)
          let inputData = await prepareTransaction({
            charon,
            tokenAddress: token.address,
            inputs:[],
            outputs: [aliceDepositUtxo],
            account: {
              owner: sender.address,
              publicKey: aliceDepositUtxo.keypair.address(),
            },
            privateChainID: 2,
            myHasherFunc: poseidon,
            myHasherFunc2: poseidon2
          })
          let args = inputData.args
          let extData = inputData.extData
          await token.connect(accounts[1]).approve(charon.address,_amount)
          await charon.connect(accounts[1]).depositToOtherChain(args,extData,token.address);
          let dataEncoded = await ethers.utils.AbiCoder.prototype.encode(
            ['bytes','uint256','bytes32'],
            [args.proof,args.publicAmount,args.root]
          );
          assert(await charon.getDepositIdByCommitmentHash(h.hash(dataEncoded)) == 1, "reverse commitment mapping should work")
          aliceDepositUtxo = new Utxo({ amount: _amount,myHashFunc: poseidon, chainID: 2, tokenAddress: token.address })
          inputData = await prepareTransaction({
            charon,
            tokenAddress: token.address,
            inputs:[],
            outputs: [aliceDepositUtxo],
            account: {
              owner: sender.address,
              publicKey: aliceDepositUtxo.keypair.address(),
            },
            privateChainID: 2,
            myHasherFunc: poseidon,
            myHasherFunc2: poseidon2
          })
          args = inputData.args
          extData = inputData.extData
          await token.connect(accounts[1]).approve(charon.address,_amount)
          await charon.connect(accounts[1]).depositToOtherChain(args,extData,token.address);
          dataEncoded = await ethers.utils.AbiCoder.prototype.encode(
            ['bytes','uint256','bytes32'],
            [args.proof,args.publicAmount,args.root]
          );
          assert(await charon.getDepositIdByCommitmentHash(h.hash(dataEncoded)) == 2, "reverse commitment mapping should work")
        })
        it("getOracleSubmission",async function() {
          const sender = accounts[0]
          await token.mint(accounts[1].address,web3.utils.toWei("100"))
          let _amount = utils.parseEther('10');
          let aliceDepositUtxo = new Utxo({ amount: _amount,myHashFunc: poseidon, chainID: 2, tokenAddress:token.address })
          charon = charon.connect(sender)
          let inputData = await prepareTransaction({
            charon,
            inputs:[],
            tokenAddress: token.address,
            outputs: [aliceDepositUtxo],
            account: {
              owner: sender.address,
              publicKey: aliceDepositUtxo.keypair.address(),
            },
            privateChainID: 2,
            myHasherFunc: poseidon,
            myHasherFunc2: poseidon2
          })
          let args = inputData.args
          let extData = inputData.extData
          await token.connect(accounts[1]).approve(charon.address,_amount)
          await charon.connect(accounts[1]).depositToOtherChain(args,extData,token.address);
          let dataEncoded = await getTellorSubmission(args,extData);
          let subData = await charon.getOracleSubmission(1)
          assert(subData == dataEncoded, "oracle getter should work")
        })
        it("Test getPartnerContracts()", async function() {
          let pC = await charon.getPartnerContracts();
          assert(pC[0][0] == 2, "partner chain should be correct")
          assert(pC[0][1] == charon2.address, "partner address should be correct")
        })
        it("Test isSpent()", async function() {
            await token.mint(accounts[1].address,web3.utils.toWei("100"))
            let _amount = utils.parseEther('10');
            await token.connect(accounts[1]).approve(charon.address,_amount)
            const sender = accounts[0]
            const aliceDepositUtxo = new Utxo({ amount: _amount, myHashFunc: poseidon, chainID: 2, tokenAddress:token.address })
            charon = charon.connect(sender)
            let inputData = await prepareTransaction({
              charon,
              inputs:[],
              tokenAddress: token.address,
              outputs: [aliceDepositUtxo],
              account: {
                owner: sender.address,
                publicKey: aliceDepositUtxo.keypair.address(),
              },
              privateChainID: 2,
              myHasherFunc: poseidon,
              myHasherFunc2: poseidon2
            })
            let args = inputData.args
            let extData = inputData.extData
            await charon.connect(accounts[1]).depositToOtherChain(args,extData,token.address);
            const dataEncoded = await ethers.utils.AbiCoder.prototype.encode(
            ['bytes','uint256','bytes32'],
            [args.proof,args.publicAmount,args.root]
            );
            let depositId = await charon.getDepositIdByCommitmentHash(h.hash(dataEncoded))
            let _query = await getTellorData(tellor2,charon.address,1,depositId);
            let _value = await charon.getOracleSubmission(depositId);
            let _bnum = await ethers.provider.getBlockNumber();
            let _evmCallVal = await ethers.utils.AbiCoder.prototype.encode(
              ['bytes','uint256'],
              [await ethers.utils.AbiCoder.prototype.encode(['bytes'],[_value]),_bnum]
            );
            await tellor2.submitValue(_query.queryId, _evmCallVal,_query.nonce, _query.queryData);
            await h.advanceTime(86400)//wait 12 hours
            _encoded = await ethers.utils.AbiCoder.prototype.encode(['uint256'],[depositId]);
            await charon2.oracleDeposit([0],_encoded);
            let bobSendAmount = utils.parseEther('4')
            const bobKeypair = new Keypair({myHashFunc:poseidon}) // contains private and public keys
 // contains private and public keys
            const bobAddress = await bobKeypair.address() // contains only public key
            const bobSendUtxo = new Utxo({ amount: bobSendAmount,myHashFunc: poseidon, keypair: bobKeypair, chainID: 2, tokenAddress: token.address })
            let aliceChangeUtxo = new Utxo({
                amount: _amount.sub(bobSendAmount),
                myHashFunc: poseidon,
                keypair: aliceDepositUtxo.keypair,
                chainID: 2,
                tokenAddress: token.address
            })
            inputData = await prepareTransaction({
                charon: charon2,
                tokenAddress: token.address,
                inputs:[aliceDepositUtxo],
                outputs: [bobSendUtxo, aliceChangeUtxo],
                privateChainID: 2,
                myHasherFunc: poseidon,
                myHasherFunc2: poseidon2
              })
            args = inputData.args
            extData = inputData.extData
            assert(await charon2.isSpent(args.inputNullifiers[0]) == false, "should not have spent nulifier")
            await charon2.transact(args,extData,token.address)
            assert(await charon2.isSpent(args.inputNullifiers[0]) == true, "should have spent nulifier")
        });
        it("Test _transact and _verify", async function() {
          //can't transact twice on same input, can't use a bogus proof
        await token.mint(accounts[1].address,web3.utils.toWei("100"))
        let _amount = utils.parseEther('10');
        await token.connect(accounts[1]).approve(charon.address,_amount)
        const sender = accounts[0]
        const aliceDepositUtxo = new Utxo({ amount: _amount, myHashFunc: poseidon, chainID: 2, tokenAddress: token.address })
        const fakeDepositUtxo = new Utxo({ amount: _amount, myHashFunc: poseidon, chainID: 3, tokenAddress: token.address })
        charon = charon.connect(sender)
        let inputData = await prepareTransaction({
          charon,
          tokenAddress: token.address,
          inputs:[],
          outputs: [aliceDepositUtxo],
          account: {
            owner: sender.address,
            publicKey: aliceDepositUtxo.keypair.address(),
          },
          privateChainID: 2,
          myHasherFunc: poseidon,
          myHasherFunc2: poseidon2
        })
        charon = charon.connect(sender)
        let inputDataFake;
        try{
            inputDataFake = await prepareTransaction({
            charon,
            inputs:[],
            tokenAddress: token.address,
            outputs: [fakeDepositUtxo],
            account: {
              owner: sender.address,
              publicKey: fakeDepositUtxo.keypair.address(),
            },
            privateChainID: 2,
            myHasherFunc: poseidon,
            myHasherFunc2: poseidon2
          })}
          catch{
            console.log("good catch on bad deposit UTXO")
          }
        let args = inputData.args
        let extData = inputData.extData
        await token.connect(accounts[1]).approve(charon.address,web3.utils.toWei("10000"))
        await charon.connect(accounts[1]).depositToOtherChain(args,extData,token.address);
        const dataEncoded = await ethers.utils.AbiCoder.prototype.encode(
        ['bytes','uint256','bytes32'],
        [args.proof,args.publicAmount,args.root]
        );
        let depositId = await charon.getDepositIdByCommitmentHash(h.hash(dataEncoded))
        let _query = await getTellorData(tellor2,charon.address,1,depositId);
        let _value = await charon.getOracleSubmission(depositId);
        let _bnum = await ethers.provider.getBlockNumber();
        let _evmCallVal = await ethers.utils.AbiCoder.prototype.encode(
          ['bytes','uint256'],
          [await ethers.utils.AbiCoder.prototype.encode(['bytes'],[_value]),_bnum]
        );
        await tellor2.submitValue(_query.queryId, _evmCallVal,_query.nonce, _query.queryData);
        await h.advanceTime(86400)//wait 12 hours
        _encoded = await ethers.utils.AbiCoder.prototype.encode(['uint256'],[depositId]);
        await charon2.oracleDeposit([0],_encoded);
        depositId = await charon.getDepositIdByCommitmentHash(h.hash(dataEncoded))
        _query = await getTellorData(tellor2,charon.address,1,depositId);
        // Alice sends some funds to withdraw (ignore bob)
        let bobSendAmount = utils.parseEther('4')
        const bobKeypair = new Keypair({myHashFunc:poseidon}) // contains private and public keys
// contains private and public keys
        const bobAddress = await bobKeypair.address() // contains only public key
        const bobSendUtxo = new Utxo({ amount: bobSendAmount,myHashFunc: poseidon, keypair: bobKeypair, chainID: 2, tokenAddress: token.address})
        let aliceChangeUtxo = new Utxo({
            amount: _amount.sub(bobSendAmount),
            myHashFunc: poseidon,
            keypair: aliceDepositUtxo.keypair,
            chainID: 2,
            tokenAddress: token.address
        })
        inputData = await prepareTransaction({
            charon: charon2,
            tokenAddress: token.address,
            inputs:[aliceDepositUtxo],
            outputs: [bobSendUtxo, aliceChangeUtxo],
            privateChainID: 2,
            myHasherFunc: poseidon,
            myHasherFunc2: poseidon2
          })
          let failVar = 0;
          try{
            await prepareTransaction({
            charon: charon2,
            tokenAddress: token.address,
            inputs:[fakeDepositUtxo],
            outputs: [bobSendUtxo, aliceChangeUtxo],
            privateChainID: 2,
            myHasherFunc: poseidon,
            myHasherFunc2: poseidon2
          })
          failVar = 1;
        }
        catch{
          console.log("failing as expected for fake deposit")
        }
        assert(failVar == 0, "should not allow you to use fake deposit")
        args = inputData.args
        extData = inputData.extData
        await charon2.transact(args,extData,token.address)
        await h.expectThrow(charon2.transact(args,extData,token.address))
        //add transact16
        const bobSendUtxo2 = new Utxo({ amount: bobSendAmount,myHashFunc: poseidon, keypair: bobKeypair , chainID: 2, tokenAddress: token.address})
        let aliceChangeUtxo2 = new Utxo({
            amount: _amount.sub(bobSendAmount),
            myHashFunc: poseidon,
            keypair: aliceChangeUtxo.keypair,
            chainID: 2,
            tokenAddress: token.address
        })
        inputData = await prepareTransaction({
            charon: charon2,
            tokenAddress: token.address,
            inputs:[aliceChangeUtxo],
            outputs: [bobSendUtxo2, aliceChangeUtxo2],
            privateChainID: 2,
            myHasherFunc: poseidon,
            myHasherFunc2: poseidon2
          })
        args = inputData.args
        extData = inputData.extData
        await charon2.transact(args,extData,token.address)
        //second w/ more
        let charlieSendAmount = utils.parseEther('7')
        const charlieKeypair = new Keypair({myHashFunc:poseidon}) // contains private and public keys
        // contains private and public keys
                   const charlieAddress = await charlieKeypair.address() // contains only public key
                   const charlieSendUtxo = new Utxo({ amount: charlieSendAmount,myHashFunc: poseidon, keypair: Keypair.fromString(charlieAddress,poseidon), chainID: 2, tokenAddress: token.address })
                   let bobChangeUtxo = new Utxo({
                       amount: utils.parseEther('1'),
                       myHashFunc: poseidon,
                       keypair: bobSendUtxo.keypair,
                       chainID: 2,
                       tokenAddress: token.address
                   })
                   inputData = await prepareTransaction({
                       charon: charon2,
                       tokenAddress: token.address,
                       inputs:[bobSendUtxo, bobSendUtxo2],
                       outputs: [bobChangeUtxo,charlieSendUtxo],
                       privateChainID: 2,
                       tokenAddress: token.address,
                       myHasherFunc: poseidon,
                       myHasherFunc2: poseidon2
                     })
                    try{
                      inputDataFake = await prepareTransaction({
                      charon: charon2,
                      tokenAddress: token.address,
                      inputs:[bobSendUtxo, bobSendUtxo2],
                      outputs: [bobChangeUtxo,charlieSendUtxo],
                      privateChainID: 3,
                      myHasherFunc: poseidon,
                      myHasherFunc2: poseidon2
                    })
                    failVar = 1
                  }
                  catch{
                    console.log("failing as expected for wrong chain")
                  }
                  assert(failVar == 0, "should fail on wrong chain prep")
                   args = inputData.args
                   extData = inputData.extData
                   await charon2.transact(args,extData,token.address)
                   await h.expectThrow(charon2.transact(args,extData,token.address))
    })

async function getTellorData(tInstance,cAddress,chain,depositID){
  let ABI = ["function getOracleSubmission(uint256 _depositId)"];
  let iface = new ethers.utils.Interface(ABI);
  let funcSelector = iface.encodeFunctionData("getOracleSubmission", [depositID])

  queryData = abiCoder.encode(
      ['string', 'bytes'],
      ['EVMCall', abiCoder.encode(
          ['uint256','address','bytes'],
          [chain,cAddress,funcSelector]
      )]
      );
      queryId = h.hash(queryData)
      nonce = await tInstance.getNewValueCountbyQueryId(queryId)
      return({queryData: queryData,queryId: queryId,nonce: nonce})
}

async function getTellorSubmission(args,extData){
  const dataEncoded = abiCoder.encode(
    ['bytes32','bytes32','bytes32','bytes32','bytes','bytes','bytes'],
    [
      args.inputNullifiers[0],
      args.inputNullifiers[1],
      args.outputCommitments[0],
      args.outputCommitments[1],
      args.proof,
      extData.encryptedOutput1,
      extData.encryptedOutput2
    ]
  );
  return dataEncoded;
}

});