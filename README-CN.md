
## Build

1.进入源码根目录

2.
make bootnode
make gdcrm

## Run

启动程序，默认至少三个节点：

1.启动bootnode
./build/bin/bootnode --genkey ./bootnode.key
./build/bin/bootnode --nodekey ./bootnode.key --addr :12340

然后找到屏幕输出的“UDP listener up,
bootnodes”，拷贝后面的enode字段，比如：enode://4a6a6af8f4a729b3d36c6e333610d9676be759041b54af53d77d064f9f91bebaf14f03f257d79cd8c7aa824964dbae98a6981f9a575313a8eac22d62038a8b33@[::]:12340，其中[::]填入具体机器ip，本地的话写127.0.0.1，比如：enode://8ba3d01a533b44b18b833e308e36335c906f2e21621e076659d828a2e8f41a5bf21dbf914c4a32e7c35755b28d0204bb129ce07da57d00027788885ddf6cacec@127.0.0.1:12340

2.按顺序分别启动三个节点

//第一个节点
./build/bin/gdcrm --rpcport 9010 --bootnodes
"enode://4a6a6af8f4a729b3d36c6e333610d9676be759041b54af53d77d064f9f91bebaf14f03f257d79cd8c7aa824964dbae98a6981f9a575313a8eac22d62038a8b33@127.0.0.1:12340"
--port 12341 --nodekey "node1.key"   

//第二个节点
./build/bin/gdcrm --rpcport 9011 --bootnodes
enode://e9d51341d96909c21e6e7bc4332f2be6b3511c7a0638719618db0496a70dc32d18f14bca34efec2c898aa108e2f3a228f2963fcf9cc62f692878fc79cbab2d73@127.0.0.1:12340
--port 12342 --nodekey "node2.key" 

//第三个节点
./build/bin/gdcrm --rpcport 9012 --bootnodes
enode://e9d51341d96909c21e6e7bc4332f2be6b3511c7a0638719618db0496a70dc32d18f14bca34efec2c898aa108e2f3a228f2963fcf9cc62f692878fc79cbab2d73@127.0.0.1:12340
--port 12343 --nodekey "node3.key" 

## API

1.rpc调用默认不发往第一个节点跟第二个节点，否则拒绝执行。

rpc调用示例（curl命令）：

//dcrm公钥生成。（发往第三个节点）
curl -X POST -H "Content-Type":application/json --data '{"jsonrpc":"2.0","method":"dcrm_reqAddr","params":[],"id":67}' http://127.0.0.1:9012

//dcrm sign。（发往第三个节点）
curl -X POST -H "Content-Type":application/json --data '{"jsonrpc":"2.0","method":"dcrm_sign","params":["046637ce9e78efb18d3ff343bf9bb648dd8875d6899b6228b042adc889bdfc3f89596902d5d1b6d4086f8fb2aa42e830b4e5e09cd688f01e6f4f018387ec76e337","0x19b6236d2e7eb3e925d0c6e8850502c1f04822eb9aa67cb92e5004f7017e5e41"],"id":67}' http://127.0.0.1:9012

其中046637ce9e78efb18d3ff343bf9bb648dd8875d6899b6228b042adc889bdfc3f89596902d5d1b6d4086f8fb2aa42e830b4e5e09cd688f01e6f4f018387ec76e337
是dcrm_reqAddr得到的pubkey，0x19b6236d2e7eb3e925d0c6e8850502c1f04822eb9aa67cb92e5004f7017e5e41是待签名的hash，要求格式必须是0x开头的16进制32字节字符串。

