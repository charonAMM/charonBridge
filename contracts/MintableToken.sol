//SPDX-License-Identifier: Unlicense
pragma solidity 0.8.17;

import "./Token.sol";

/**
 @title mintabletoken
**/    
contract MintableToken is Token{

    //storage
    address public controller;//address of the controller contract
    address public nativeAddress;

    //events
    event TokenMinted(address _to, uint256 _amount);
    event TokenBurned(address _from, uint256 _amount);

    //functions
    /**
     * @dev constructor to initialize contract and token
     */
    constructor(address _controller, address _nativeAddress, string memory _name, string memory _symbol) Token(_name,_symbol){
        controller = _controller;
        nativeAddress = _nativeAddress;
    }

    /**
     * @dev allows the controller to burn tokens of users
     * @param _from address to burn tokens of
     * @param _amount amount of tokens to burn
     */
    function burn(address _from, uint256 _amount) external{
        require(msg.sender == controller);
        _burn(_from, _amount);
        emit TokenBurned(_from,_amount);
    }
    
    /**
     * @dev allows the controller to mint chd tokens
     * @param _to address to mint tokens to
     * @param _amount amount of tokens to mint
     */
    function mint(address _to, uint256 _amount) external{
        require(msg.sender == controller);
        _mint(_to,_amount);
        emit TokenMinted(_to,_amount);
    }
}