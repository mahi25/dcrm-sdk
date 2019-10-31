
## Build

make bootnode

make gdcrm

## Run

At least three nodes by default.

1. Run bootnode

./build/bin/bootnode --genkey ./bootnode.key

./build/bin/bootnode --nodekey ./bootnode.key --addr :12340 --group 0

2. Run dcrm node

Get "enode" field from the first step,for example: 
enode://16ab118525ec559dde2640b513676b8df7368aac3a80cc5c9d9e8b9c71781c09103fe3e8b5dd17bf245f0c71b891ec4848b142852763ab2146a1e288df15da40@[::]:12340

//Run first node

./build/bin/gdcrm --rpcport 9010 --bootnodes "enode://16ab118525ec559dde2640b513676b8df7368aac3a80cc5c9d9e8b9c71781c09103fe3e8b5dd17bf245f0c71b891ec4848b142852763ab2146a1e288df15da40@127.0.0.1:12340" --port 12341 --nodekey "node1.key"   

//Run second node

./build/bin/gdcrm --rpcport 9011 --bootnodes enode://16ab118525ec559dde2640b513676b8df7368aac3a80cc5c9d9e8b9c71781c09103fe3e8b5dd17bf245f0c71b891ec4848b142852763ab2146a1e288df15da40@127.0.0.1:12340 --port 12342 --nodekey "node2.key" 

//Run third node

./build/bin/gdcrm --rpcport 9012 --bootnodes enode://16ab118525ec559dde2640b513676b8df7368aac3a80cc5c9d9e8b9c71781c09103fe3e8b5dd17bf245f0c71b891ec4848b142852763ab2146a1e288df15da40@127.0.0.1:12340 --port 12343 --nodekey "node3.key" 

## API

Rpc calls are not sent to the first node and second node by default,otherwise they will be rejected.

for example:

//generate pubkey.(sent to the third node)

curl -X POST -H "Content-Type":application/json --data '{"jsonrpc":"2.0","method":"dcrm_reqAddr","params":[],"id":67}' http://127.0.0.1:9012

//dcrm sign.(sent to the third node)

curl -X POST -H "Content-Type":application/json --data '{"jsonrpc":"2.0","method":"dcrm_sign","params":["046637ce9e78efb18d3ff343bf9bb648dd8875d6899b6228b042adc889bdfc3f89596902d5d1b6d4086f8fb2aa42e830b4e5e09cd688f01e6f4f018387ec76e337","0x19b6236d2e7eb3e925d0c6e8850502c1f04822eb9aa67cb92e5004f7017e5e41"],"id":67}' http://127.0.0.1:9012

First argument: the pubkey from dcrm_reqAddr call.

Second argument: the hash want to sign.it must be 16-in-32-byte character sprang at the beginning of 0x. 
for example,0x19b6236d2e7eb3e925d0c6e8850502c1f04822eb9aa67cb92e5004f7017e5e41

