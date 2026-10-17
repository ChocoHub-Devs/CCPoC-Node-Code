# 🌱 CCPoC - a decentralized Proof-of-Capacity network

![Chain Height](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fseed1.chocohub.org%2Fapi%2Fstats&label=chain%20height&query=%24.height&color=blue)
![Reward](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fseed1.chocohub.org%2Fapi%2Fstats&label=block%20reward&query=%24.current_reward_cc&color=gold)
![Max Supply](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fseed1.chocohub.org%2Fapi%2Fstats&label=max%20supply&query=%24.max_supply&color=blueviolet)
![Capacity](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fseed1.chocohub.org%2Fapi%2Fstats&query=%24.capacity_gb&label=capacity&suffix=%20GB&color=teal)

Hello CC Node runner! Lets get straight to the point on how to setup:

## 1. Dependencies & Requirements:

## Requirements:

| Item | Details |
|---|---|
| **Node.js** | **22.x** [Download](https://nodejs.org/en/download) |
| **A public URL** | Other nodes must be able to reach yours. Use **port forwarding** (best option) or a tunnel such as [cloudflared](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/downloads/) (or ngrok). |
| **A CCPoC wallet** | An `0x...` address and its private key. |
| **Hardware** | See [Hardware](#hardware) below. |
 
### Hardware
 
The node is **I/O bound**, so it barely uses your hardware.
 
| | Without smart contracts | With smart contracts |
|---|---|---|
| **CPU** | Any modest office CPU or basic laptop CPU is enough. | A stronger, dedicated CPU with spare threads. |
| **RAM** | 4 GB total (the node itself uses ~60 MB; keep 1-2 GB free as headroom). | 4 GB or more, since the EVM need extra memory. |
| **Network** | At least **2 MB/s** (≈ 16 Mbps). Blocks are capped at 2 MB. | Same. |
 
**Storage**
 
| Node type | Minimum | Notes |
|---|---|---|
| **Light node** | 32 GB | Keeps the last 8192 blocks. At the 2 MB block cap that is ~16 GB, so leave room to spare. |
| **Full node** | 1 TB | Even though the chain is small today, it will grow. |

## Dependencies:

Firstly, for running a node, make sure you have node js installed on your pc;
> Dont have it installed? Download here -> https://nodejs.org/en/download

Make sure to have cloudflared tunnel installed too! (or ngrok, but port fowarding is the best option!)
> Dont have it installed? Download here -> https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/downloads/

### 2. Configurating:

Firstly, go to config folder, at the config.env file add your credentials;

# Node url:
the node url parameter must be your public url or ip + port, pointing to the same port as node
e.g.:
NODE_URL=https://seed1.chocohub.org 

# Seed Peers:
the seed peers must be other public nodes url, separated by ","
e.g.:
SEED_PEERS=https://ccpoc-node-code-production.up.railway.app,https://seed1.chocohub.org

# Port:
the port number is the port your node will be running, make sure its the same port as your tunnel!
e.g.:
PORT=3001

# MINER ADDRESS:
the miner adress credential is your ccpoc wallet address (0x), make sure to have one!
e.g.:
MINER_ADDRESS=0xfcd52c1add54ae78ea435264c9541cc351076dc5

# MINER PRIVATE_KEY: 
The private key is the key use by node to sign blocks, its mandatory to have one.
e.g.:
MINER_PRIVATE_KEY=350b847855d98fb1fee571976dd132be1a5455923ee24dc4abcdefghijklmnop

# BLOCK TIME
The block time is the expected time per block, that node uses to adjust BT (base target), make sure to use 120s (mandatory, or your node will generate a fork or all your blocks will be rejected)
e.g.:
BLOCK_TIME=120

# ADMIN TOKEN
A token used by an admin (you, or someone that you give the token) to manage your node, you can set your own (if you dont set, will be random)
e.g.:
ADMIN_TOKEN=6ea85a11882524581a14543573405dba

# LOG LEVEL
The level of logging by node (5 levels: trace | debug | info | warn | error), recommended is "debug".
e.g.:
LOG_LEVEL=debug

# Syncing:
the amount of blocks per sync and sync ms, requesting more than those numbers will cause a rate limit;
e.g.:
SYNC_MS=1000
MAX_BLOCKS_PER_SYNC=1000

# Mempool:
the max mempool size for you node to include in a block, remember: higher number requires more gas, therefore; more compute is required.
e.g.:
MAX_MEMPOOL_SIZE=5000

# SMART CONTRACTS:
wheter node will have smart contracts enabled or not, enabled requires better hardware, but you can earn fees!
e.g.:
SMART_CONTRACTS_ENABLED=true

### 3. Running a node:

Firstly, run: "npm install" for downloading all node modules and dependencies, may take some time!
then run: "npm start" or "node chocohub.js"

### Windows note
 
The node uses `better-sqlite3`, If `npm install` fails on Windows, install the
[Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) (C++ workload) and Python, then try again.
 
---

and here we are, you are running a node!
