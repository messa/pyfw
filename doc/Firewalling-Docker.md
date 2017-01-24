Firewalling Docker
==================

Imagine this situation:

    Network   +------------------------------+
              | Docker Host                  |   Virtual Docker network:
        |     | eth0:             docker0:   |       +------------------------------+
        +-----| 192.168.122.190   172.17.0.1 |---+   | Docker container 1           |
        |     +------------------------------+   +---| eth0: 172.17.0.2             |
        |                                        |   | (running nginx on port 8000) |
        |     +------------------------------+   |   +------------------------------+
        |     | Host 2                       |   |   | Docker container 2           |
        +-----| eth0: 192.168.122.193        |   +---| eth0: 172.17.0.3             |
        |     +------------------------------+       +------------------------------+

Our goal:

- All Docker containers on Docker Host can connect to 172.17.0.1:8000
- Host 2 (192.168.122.193) can connect to 192.168.122.190:8000 (to talk with Docker container 1)
- No other hosts (other than Host 2) can connect to 192.168.122.190:8000

This is how iptables-save looks like just after running Docker and `docker run -d -p 8000:80 nginx`:

    *nat
    :PREROUTING ACCEPT [0:0]
    :INPUT ACCEPT [0:0]
    :OUTPUT ACCEPT [0:0]
    :POSTROUTING ACCEPT [0:0]
    :DOCKER - [0:0]
    -A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER
    -A OUTPUT ! -d 127.0.0.0/8 -m addrtype --dst-type LOCAL -j DOCKER
    -A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE
    -A POSTROUTING -s 172.17.0.2/32 -d 172.17.0.2/32 -p tcp -m tcp --dport 80 -j MASQUERADE
    -A DOCKER -i docker0 -j RETURN
    -A DOCKER ! -i docker0 -p tcp -m tcp --dport 8000 -j DNAT --to-destination 172.17.0.2:80
    COMMIT
    *filter
    :INPUT ACCEPT [39:2172]
    :FORWARD DROP [0:0]
    :OUTPUT ACCEPT [35:3776]
    :DOCKER - [0:0]
    :DOCKER-ISOLATION - [0:0]
    -A FORWARD -j DOCKER-ISOLATION
    -A FORWARD -o docker0 -j DOCKER
    -A FORWARD -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    -A FORWARD -i docker0 ! -o docker0 -j ACCEPT
    -A FORWARD -i docker0 -o docker0 -j ACCEPT
    -A DOCKER -d 172.17.0.2/32 ! -i docker0 -o docker0 -p tcp -m tcp --dport 80 -j ACCEPT
    -A DOCKER-ISOLATION -j RETURN
    COMMIT
