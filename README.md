
## Build

make bootnode

make gdcrm

## Run

./build/bin/gdcrm

## JSON RPC API

Default rpc port: 9012

#### dcrm_genPubkey

generate dcrm pubkey.

##### Parameters

none

##### Return

`error` - error info.

`pubkey` - dcrm pubkey.

##### Example

// Request
curl -X POST -H "Content-Type":application/json --data '{"jsonrpc":"2.0","method":"dcrm_genPubkey","params":[],"id":67}' http://127.0.0.1:9012

// Result
{
"error":"",
"pubkey":"049ac626ee0f0f79a49d6ed37f14ff2ad4e4f45fddf6e5293bcaa6a607e5392b49dde27a8f0602e23bc5fa0b847bd28d46e2f2d1d0d8cf59514785e4276b28de9d"
}

#### dcrm_sign

dcrm sign.

##### Parameters

1. `DATA`,pubkey - the pubkey from dcrm_genPubkey request.
2. `String|HexNumber|TAG` - the hash want to sign.it must be 16-in-32-byte character sprang at the beginning of 0x,for example,0x19b6236d2e7eb3e925d0c6e8850502c1f04822eb9aa67cb92e5004f7017e5e41.

##### Return

`error` - error info.

`rsv` - signature str.

##### Example

// Request
curl -X POST -H "Content-Type":application/json --data '{"jsonrpc":"2.0","method":"dcrm_sign","params":["049ac626ee0f0f79a49d6ed37f14ff2ad4e4f45fddf6e5293bcaa6a607e5392b49dde27a8f0602e23bc5fa0b847bd28d46e2f2d1d0d8cf59514785e4276b28de9d","0x19b6236d2e7eb3e925d0c6e8850502c1f04822eb9aa67cb92e5004f7017e5e41"],"id":67}' http://127.0.0.1:9012

// Result
{
"error":"",
"rsv":"FFBB398B95ED2ED308B0FE87BC254FFC2C9957742EA05C18A1411C672B74FBDF6FBD6F4915799F2B4186192581D4506039ADEB79C8EB954E779901FDB9575C8301"
}

## Run Local

At least three nodes by default.

#### Run bootnode

./build/bin/bootnode --genkey ./bootnode.key

./build/bin/bootnode --nodekey ./bootnode.key --addr :12340 --group 0

#### Run dcrm node

##### Get "enode" field from the first step

for example: 
enode://16ab118525ec559dde2640b513676b8df7368aac3a80cc5c9d9e8b9c71781c09103fe3e8b5dd17bf245f0c71b891ec4848b142852763ab2146a1e288df15da40@[::]:12340

##### Run first node

./build/bin/gdcrm --rpcport 9010 --bootnodes "enode://16ab118525ec559dde2640b513676b8df7368aac3a80cc5c9d9e8b9c71781c09103fe3e8b5dd17bf245f0c71b891ec4848b142852763ab2146a1e288df15da40@127.0.0.1:12340" --port 12341 --nodekey "node1.key"   

##### Run second node

./build/bin/gdcrm --rpcport 9011 --bootnodes enode://16ab118525ec559dde2640b513676b8df7368aac3a80cc5c9d9e8b9c71781c09103fe3e8b5dd17bf245f0c71b891ec4848b142852763ab2146a1e288df15da40@127.0.0.1:12340 --port 12342 --nodekey "node2.key" 

##### Run third node

./build/bin/gdcrm --rpcport 9012 --bootnodes enode://16ab118525ec559dde2640b513676b8df7368aac3a80cc5c9d9e8b9c71781c09103fe3e8b5dd17bf245f0c71b891ec4848b142852763ab2146a1e288df15da40@127.0.0.1:12340 --port 12343 --nodekey "node3.key" 
