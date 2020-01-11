pragma solidity ^0.5.4;

contract Masternode {

    uint public constant nodeCost = 10000 * 10**18;
    uint public constant baseCost = 10**18;
    uint public constant minBlockTimeout = 800;
    uint public constant miningPeriod = 86400 / 3 * 365;

    bytes8 public lastId;
    bytes8 public lastOnlineId;
    uint public countTotalNode;
    uint public countOnlineNode;
    uint public countExpiredNode;

    struct node {
        bytes32 id1;
        bytes32 id2;
        bytes8 preId;
        bytes8 nextId;
        bytes8 preOnlineId;
        bytes8 nextOnlineId;
        address payable coinbase;
        uint status;
        uint blockEnd;
        uint blockRegister;
        uint blockLastPing;
        uint blockOnline;
        uint blockOnlineAcc;
        address referrer;
    }

    mapping (bytes8 => node) public nodes;
    mapping (address => bytes8) nodeAddressToId;
    mapping (address => bytes8[]) public idsOf;
    mapping (address => bytes8[]) public refIdsOf;
    mapping (address => uint) public expiredNodesOf;

    event join(bytes8 id, address addr);
    event quit(bytes8 id, address addr);

    function register(bytes32 id1, bytes32 id2, address ref) public payable{
        bytes8 id = bytes8(id1);
        require(
            bytes8(0) != id &&
            bytes32(0) != id1 &&
            bytes32(0) != id2 &&
            bytes32(0) == nodes[id].id1 &&
            address(0) != ref &&
            msg.value == nodeCost
        );
        bytes32[2] memory input;
        address payable[1]  memory output;
        input[0] = id1;
        input[1] = id2;
        assembly {
            if iszero(call(not(0), 0x0b, 0, input, 128, output, 32)) {
                revert(0, 0)
            }
        }
        address payable account = output[0];
        require(account != address(0));
        nodeAddressToId[account] = id;
        nodes[id] = node(
            id1,id2,
            lastId,bytes8(0),
            bytes8(0),bytes8(0),
            msg.sender,1,
            block.number + miningPeriod,
            block.number,0,0,0,
            ref
        );
        if(lastId != bytes8(0)){
            nodes[lastId].nextId = id;
        }
        lastId = id;
        idsOf[msg.sender].push(id);
        refIdsOf[ref].push(id);
        countTotalNode += 1;
        account.transfer(baseCost);
        emit join(id, msg.sender);
    }

    function reset(bytes32 id1, bytes32 id2, bytes8 oldId) public payable{
        bytes8 id = bytes8(id1);
        require(
            bytes8(0) != id &&
            bytes32(0) != id1 &&
            bytes32(0) != id2 &&
            bytes32(0) == nodes[id].id1 &&
            bytes32(0) != nodes[oldId].id1 &&
            msg.sender == nodes[oldId].coinbase &&
            nodes[oldId].blockEnd > block.number &&
            msg.value == 10 * 10 ** 18
        );
        bytes32[2] memory input;
        address payable[1]  memory output;
        input[0] = id1;
        input[1] = id2;
        assembly {
            if iszero(call(not(0), 0x0b, 0, input, 128, output, 32)) {
                revert(0, 0)
            }
        }
        address payable account = output[0];
        require(account != address(0));
        nodeAddressToId[account] = id;
        uint endBlock = nodes[oldId].blockEnd;
        address ref = nodes[oldId].referrer;
        nodes[oldId].blockEnd = block.number;
        nodes[oldId].status = 3;
        nodes[id] = node(
            id1,id2,
            lastId,bytes8(0),
            bytes8(0),bytes8(0),
            msg.sender,1,
            endBlock,
            block.number,
            0, 0, 0,
            ref
        );

        if(lastId != bytes8(0)){
            nodes[lastId].nextId = id;
        }
        lastId = id;
        idsOf[msg.sender].push(id);
        refIdsOf[ref].push(id);
        countTotalNode += 1;
        account.transfer(baseCost);
        emit quit(oldId, msg.sender);
        emit join(id, msg.sender);
    }

    function renew(bytes8 id) public payable{
        require(nodes[id].status != 0 &&
        msg.value == nodeCost &&
        msg.sender == nodes[id].coinbase);
        nodes[id].blockEnd += miningPeriod;
        if(nodes[id].status == 2){
            countExpiredNode -= 1;
            expiredNodesOf[nodes[id].coinbase] -= 1;
            if(lastId != bytes8(0)){
                nodes[lastId].nextId = id;
            }
            lastId = id;
            emit join(id, msg.sender);
        }
    }

    function() external {
        bytes8 id = nodeAddressToId[msg.sender];
        if (id != bytes8(0) && nodes[id].status == 1){
            if(0 == nodes[id].blockOnline){
                nodes[id].blockOnline = 1;
                countOnlineNode += 1;
                if(lastOnlineId != bytes8(0)){
                    nodes[lastOnlineId].nextOnlineId = id;
                }
                nodes[id].preOnlineId = lastOnlineId;
                nodes[id].nextOnlineId = bytes8(0);
                lastOnlineId = id;
            }else if(nodes[id].blockLastPing > 0){
                uint blockGap = block.number - nodes[id].blockLastPing;
                if(blockGap > minBlockTimeout){
                    nodes[id].blockOnline = 1;
                }else{
                    nodes[id].blockOnline += blockGap;
                    nodes[id].blockOnlineAcc += blockGap;
                }
            }
            nodes[id].blockLastPing = block.number;
            fix(nodes[id].preOnlineId);
            fix(nodes[id].nextOnlineId);
        }
    }

    function fix(bytes8 id) internal {
        if (id != bytes8(0) && nodes[id].id1 != bytes32(0)){
            if(countOnlineNode > 21 && block.number > nodes[id].blockEnd){
                offline(id);
                bytes8 preId = nodes[id].preId;
                bytes8 nextId = nodes[id].nextId;
                if(preId != bytes8(0)){
                    nodes[preId].nextId = nextId;
                }
                if(nextId != bytes8(0)){
                    nodes[nextId].preId = preId;
                }else{
                    lastId = preId;
                }
                if(nodes[id].status == 1){
                    nodes[id].status = 2;
                }
                countExpiredNode += 1;
                expiredNodesOf[nodes[id].coinbase] += 1;
                emit quit(id, nodes[id].coinbase);
            }else if(nodes[id].blockLastPing > 0 && nodes[id].blockOnline > 0){
                if((block.number - nodes[id].blockLastPing) > minBlockTimeout){
                    offline(id);
                }
            }
        }
    }

    function offline(bytes8 id) internal {
        if (nodes[id].blockOnline > 0){
            countOnlineNode -= 1;
            nodes[id].blockOnline = 0;
            bytes8 preOnlineId = nodes[id].preOnlineId;
            bytes8 nextOnlineId = nodes[id].nextOnlineId;
            if(preOnlineId != bytes8(0)){
                nodes[preOnlineId].nextOnlineId = nextOnlineId;
                nodes[id].preOnlineId = bytes8(0);
            }
            if(nextOnlineId != bytes8(0)){
                nodes[nextOnlineId].preOnlineId = preOnlineId;
                nodes[id].nextOnlineId = bytes8(0);
            }else{
                lastOnlineId = preOnlineId;
            }
        }
    }

    function getInfo(address addr) view public returns (
        uint lockedBalance,
        uint releasedReward,
        uint totalNodes,
        uint onlineNodes,
        uint expiredNodes,
        uint myValidNodes,
        uint myExpiredNodes
    )
    {
        lockedBalance = address(this).balance / (10**18);
        releasedReward = block.number * 48 / 10;
        totalNodes = countTotalNode;
        onlineNodes = countOnlineNode;
        expiredNodes = countExpiredNode;
        myExpiredNodes = expiredNodesOf[addr];
        myValidNodes = idsOf[addr].length - myExpiredNodes;
    }

    function getIds(address addr, uint startPos) public view
    returns (uint length, bytes8[5] memory data) {
        bytes8[] memory myIds = idsOf[addr];
        length = uint(myIds.length);
        for(uint i = 0; i < 5 && (i+startPos) < length; i++) {
            data[i] = myIds[i+startPos];
        }
    }

    function getRefIds(address addr, uint startPos) public view
    returns (uint length, bytes8[5] memory data) {
        bytes8[] memory myIds = refIdsOf[addr];
        length = uint(myIds.length);
        for(uint i = 0; i < 5 && (i+startPos) < length; i++) {
            data[i] = myIds[i+startPos];
        }
    }

    function has(bytes8 id) view public returns (bool)
    {
        return nodes[id].id1 != bytes32(0) && nodes[id].status == 1;
    }
}