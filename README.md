# IPSec Session Hijacking

## Internet Protocol Security
- Abbreviated as IPSec, is a secure network protocol suite.
- Provide secure communication by authenticating and encrypting data packets.
- Ensure the confidentiality and integrity of the data.

## Attack Scenario
- The TCP client has set up IPsec assoications in transport mode for secure communication with a TCP server.
- The attacker executes a malicious program to hijack the IPSec/TCP session.

## Description
- Execute provided programs to establish the IPSec/TCP session.
- Develop an attacker program on client to hijack the IPSec/TCP session.
- Send specific flags (take a look at **pc/answer.txt**) to the server using the attacker program.
- With the successful hijacking, the server can reply to the flags with correct responses.

## Execution
Change the `vic_ip` and `serv_ip` to the client and server IP address respectively in **pc/ipsec_server.sh** and **pc/ipsec_client.sh**.
```bash
vic_ip='{CLIENT_IP_ADDRESS}'
serv_ip='{SERVER_IP_ADDRESS}'
```

Set up the environment via the command below.
```bash
$ sudo ./pc/ipsec_server.sh    # on the server machine
$ sudo ./pc/ipsec_client.sh    # on the client machine
```

Establish the IPSec/TCP session.
```bash
$ cd pc && make
$ sudo ./tcp_server 1111                                 # on the server machine
$ sudo ./tcp_client {SERVER_IP_ADDRESS} 1111 -bp 2222    # on the client machine
```

Open a new terminal on client machine and develop the attack program to hijack it.
```bash
$ cd codes && make
$ sudo ./ipsec_hijack {INTERFACE_NAME}
```