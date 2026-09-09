# Testnet: chain id 4 (SHRUGG, confidential computation)

Test keys only; all seeds are committed on purpose so any machine can pull and run.
Genesis hash `7e6271a3aa38f11a43a6b3ad4c2262860cc8fa4b1f5c7b3b37dd6aebae01e917`, 100 SHRUGG per validator, **faucet enabled**, **confidential computation enabled** (production FRI profile)
(`shrugg faucet [address]` mints up to 100 SHRUGG per call on any node). Quorum is 3 of 4 validators.

| node | role | where | address | peer id |
|---|---|---|---|---|
| A | validator | laptop, LAN 192.168.100.123 (NAT) | 2nRdFChBXRmKoe2sQE3ZYDzvdg53QmBZJJ9iweY7hk1v | 12D3KooWRbvv6T8iQz1jT5ijvPoo6CEGy3yRdiuxkUMJGUkTNq6P |
| B | validator | 192.168.100.79 (NAT) | ByDkxsEfDCR5DrmDufKftvcRsgvufypnZ4SgDQzJAQ7Z | 12D3KooWMUjpbd6U7c6KTjVXy3121aV6JLka47dh4ZPwGjyMV8Bf |
| C | validator | DigitalOcean 167.172.65.63 | F6rYLexPhyMmwPNqbEmyyp5FiTmtQqDgZyqScUqYY4F6 | 12D3KooWBKYD5bBRczEhzYQrN4jgfgaoGXb6PzbfdjtTjiy1SA5g |
| D | validator | DigitalOcean 178.128.91.236 | 5tMgLSzXL8keU1vg2wtGEXRJkmfBK6GzhjNjxrCFgCaj | 12D3KooWPrdUXsVXsD3RqaV4otq35awpJgMonSfdu3u8gtq5iUYq |
| E | observer | DigitalOcean 188.166.235.187 | CxeG7vJaxUoKBZZe8U8LGXohH2FvcCbE47AufK6Mp2jf | 12D3KooWR1nihpYk6vvdRYuq2WMGUtzDiwygytTXZJszdSnaVmDM |
| F | observer | DigitalOcean 157.245.156.41 | DcuuZrzDSJedhFnynLFchNfYmW4UKiZT2nEKbcs2ojmJ | 12D3KooWJwsFwi9CawJrPyA7ZBT5Q6mYWmctNvLRt3SuS7SdyU6j |

C and D have public IPs and act as bootstrap nodes; A and B are behind NAT and dial out to them
(`deploy/run-a.sh`, `deploy/run-b.sh`). Full multiaddrs are in `deploy/nodes.env`.

Droplets: `deploy/push-to-vps.sh <ip> <letter> "<bootstrap multiaddrs>" [validator|observer]` provisions from scratch;
`deploy/rebuild-vps.sh <ip>` rebuilds on new commits and restarts (data kept). Service name: `shrugg-node`.

On 192.168.100.79:
```bash
git pull && ./deploy/run-b.sh
shrugg --key deploy/node-b.key.json balance
shrugg faucet ByDkxsEfDCR5DrmDufKftvcRsgvufypnZ4SgDQzJAQ7Z        # 100 SHRUGG from the testnet faucet
shrugg --key deploy/node-b.key.json send 2nRdFChBXRmKoe2sQE3ZYDzvdg53QmBZJJ9iweY7hk1v 1.5
```

Confidential call from the laptop (private inputs never leave it):
```bash
shrugg --key deploy/node-a.key.json program build --guest private_payment --arg 1000 --out pp.json
shrugg --key deploy/node-a.key.json program deploy pp.json
shrugg --key deploy/node-a.key.json call <program-id> --input 400 --input 250 --input 300 --input 75 --to <B address>
```

History: chain 1 (2 validators, SESH) and chain 2 (4 validators + 2 observers, SESH) ran on 2026-09-09;
chain 3 followed the SESH -> SHRUGG rename and added the faucet; chain 4 (2026-09-10) adds confidential
computation (Deploy/Call) and requires Rust 1.98.1 on every node.
