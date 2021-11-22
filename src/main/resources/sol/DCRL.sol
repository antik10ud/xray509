// mvn web3j:generate-sources
pragma solidity >=0.7.0 <0.8.0;

contract DCRL {

    address owner;

    constructor()  {
        owner = msg.sender;
    }

    mapping(uint256 => bool) revoked;

    function revoke(uint256 id) public {
        require(owner == msg.sender);
        revoked[id]=true;
    }

    function has(uint256 id) public view returns (bool){
        return revoked[id];
    }

}