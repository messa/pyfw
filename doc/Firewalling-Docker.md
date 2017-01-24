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
- We want to switch INPUT default policy to DROP (because white-listing is safer than black-listing)

This is how iptables-save looks like just after running Docker and `docker run -d -p 8000:80 nginx`:

<pre>
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:DOCKER - [0:0]
-A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER
-A OUTPUT ! -d 127.0.0.0/8 -m addrtype --dst-type LOCAL -j DOCKER
-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE
<b>-A POSTROUTING -s 172.17.0.2/32 -d 172.17.0.2/32 -p tcp -m tcp --dport 80 -j MASQUERADE</b>
-A DOCKER -i docker0 -j RETURN
<b>-A DOCKER ! -i docker0 -p tcp -m tcp --dport 8000 -j DNAT --to-destination 172.17.0.2:80</b>
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
<b>-A DOCKER -d 172.17.0.2/32 ! -i docker0 -o docker0 -p tcp -m tcp --dport 80 -j ACCEPT</b>
-A DOCKER-ISOLATION -j RETURN
COMMIT
</pre>

All these rules were created by Docker engine, the bold ones are specific for the nginx container.

Check what works and what doesn't:

- connect to nginx container from Docker Host - works
- connect to nginx container from another Docker container on Docker Host - works
- connect to nginx container from Host 2 - works
- connect to nginx container from any host other than Host 2 - works (but we don't want that)

Let's make the networking on the Docker Host a bit more secure - change INPUT default policy from ACCEPT to DROP, and,
of course, add rules to allow SSH and established connections:

<pre>
$ iptables -I INPUT 1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
$ iptables -I INPUT 2 -p tcp -m tcp --dport 22 -j ACCEPT
$ iptables -P INPUT DROP
</pre>

New state of `iptables-save`:

<pre>
*nat
:PREROUTING ACCEPT [8:1266]
:INPUT ACCEPT [3:301]
:OUTPUT ACCEPT [2:144]
:POSTROUTING ACCEPT [3:204]
:DOCKER - [0:0]
-A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER
-A OUTPUT ! -d 127.0.0.0/8 -m addrtype --dst-type LOCAL -j DOCKER
-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE
-A POSTROUTING -s 172.17.0.2/32 -d 172.17.0.2/32 -p tcp -m tcp --dport 80 -j MASQUERADE
-A DOCKER -i docker0 -j RETURN
-A DOCKER ! -i docker0 -p tcp -m tcp --dport 8000 -j DNAT --to-destination 172.17.0.2:80
COMMIT
*filter
<b>:INPUT DROP [2:241]</b>
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [89:9939]
:DOCKER - [0:0]
:DOCKER-ISOLATION - [0:0]
<b>-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT</b>
<b>-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT</b>
-A FORWARD -j DOCKER-ISOLATION
-A FORWARD -o docker0 -j DOCKER
-A FORWARD -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -i docker0 ! -o docker0 -j ACCEPT
-A FORWARD -i docker0 -o docker0 -j ACCEPT
-A DOCKER -d 172.17.0.2/32 ! -i docker0 -o docker0 -p tcp -m tcp --dport 80 -j ACCEPT
-A DOCKER-ISOLATION -j RETURN
COMMIT
</pre>

Let's check again:

- connect to nginx container from Docker Host - works
- connect to nginx container from another Docker container on Docker Host - __doesn't work__ (neither to 172.17.0.1:8000 nor 192.168.122.190:8000)
- connect to nginx container from Host 2 - works
- connect to nginx container from any host other than Host 2 - works (but we don't want that)

You see, if you DROP traffic in the INPUT filter chain, in case of Docker, it actually affects
only inter-container communication (if not using direct Docker links).
You want to apply firewall to Docker traffic you have to do it in the FORWARD chain.
It is a little better to do it in the DOCKER chain that is referenced from FORWARD.

Let's fix it:

```
$ ipset create allowed_hosts hash:ip
$ ipset add allowed_hosts 192.168.122.193
$ ipset save
create allowed_hosts hash:ip family inet hashsize 1024 maxelem 65536
add allowed_hosts 192.168.122.193
$ iptables -I DOCKER ! -i docker0 -o docker0 -m set ! --match-set allowed_hosts src -j REJECT
```

New `iptables-save`:

<pre>
*nat
:PREROUTING ACCEPT [210:29161]
:INPUT ACCEPT [4:361]
:OUTPUT ACCEPT [9:843]
:POSTROUTING ACCEPT [16:1263]
:DOCKER - [0:0]
-A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER
-A OUTPUT ! -d 127.0.0.0/8 -m addrtype --dst-type LOCAL -j DOCKER
-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE
-A POSTROUTING -s 172.17.0.2/32 -d 172.17.0.2/32 -p tcp -m tcp --dport 80 -j MASQUERADE
-A DOCKER -i docker0 -j RETURN
-A DOCKER ! -i docker0 -p tcp -m tcp --dport 8000 -j DNAT --to-destination 172.17.0.2:80
COMMIT
*filter
:INPUT DROP [1:72]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [85:7888]
:DOCKER - [0:0]
:DOCKER-ISOLATION - [0:0]
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A FORWARD -j DOCKER-ISOLATION
-A FORWARD -o docker0 -j DOCKER
-A FORWARD -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -i docker0 ! -o docker0 -j ACCEPT
-A FORWARD -i docker0 -o docker0 -j ACCEPT
<b>-A DOCKER ! -i docker0 -o docker0 -m set ! --match-set allowed_hosts src -j REJECT --reject-with icmp-port-unreachable</b>
-A DOCKER -d 172.17.0.2/32 ! -i docker0 -o docker0 -p tcp -m tcp --dport 80 -j ACCEPT
-A DOCKER-ISOLATION -j RETURN
COMMIT
</pre>

What has changed?

- connect to nginx container from Docker Host - works
- connect to nginx container from another Docker container on Docker Host - still doesn't work (neither to 172.17.0.1:8000 nor 192.168.122.190:8000)
- connect to nginx container from Host 2 - works
- connect to nginx container from any host other than Host 2 - __Connection refused__, that's what we wanted

Let's fix the last thing: inter-container communication via 172.17.0.1:8000.
It looks like INPUT rules (and the default one DROP) apply here rather than FORWARD.

```
$ iptables -A INPUT -i docker0 -s 172.17.0.0/24 -j ACCEPT
```

<pre>
*nat
:PREROUTING ACCEPT [267:36850]
:INPUT ACCEPT [7:541]
:OUTPUT ACCEPT [14:1167]
:POSTROUTING ACCEPT [26:1887]
:DOCKER - [0:0]
-A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER
-A OUTPUT ! -d 127.0.0.0/8 -m addrtype --dst-type LOCAL -j DOCKER
-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE
-A POSTROUTING -s 172.17.0.2/32 -d 172.17.0.2/32 -p tcp -m tcp --dport 80 -j MASQUERADE
-A DOCKER -i docker0 -j RETURN
-A DOCKER ! -i docker0 -p tcp -m tcp --dport 8000 -j DNAT --to-destination 172.17.0.2:80
COMMIT
*filter
:INPUT DROP [2:241]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [134:15615]
:DOCKER - [0:0]
:DOCKER-ISOLATION - [0:0]
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
<b>-A INPUT -s 172.17.0.0/24 -i docker0 -j ACCEPT</b>
-A FORWARD -j DOCKER-ISOLATION
-A FORWARD -o docker0 -j DOCKER
-A FORWARD -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -i docker0 ! -o docker0 -j ACCEPT
-A FORWARD -i docker0 -o docker0 -j ACCEPT
-A DOCKER ! -i docker0 -o docker0 -m set ! --match-set allowed_hosts src -j REJECT --reject-with icmp-port-unreachable
-A DOCKER -d 172.17.0.2/32 ! -i docker0 -o docker0 -p tcp -m tcp --dport 80 -j ACCEPT
-A DOCKER-ISOLATION -j RETURN
COMMIT
</pre>

Let's check it again:

- connect to nginx container from Docker Host - works
- connect to nginx container from another Docker container on Docker Host - __works__ (both via 172.17.0.1:8000 and via 192.168.122.190:8000)
- connect to nginx container from Host 2 - works
- connect to nginx container from any host other than Host 2 - Connection refused, that's what we wanted

All our goals are fullfilled now.

So how does this translate to __pyfw__?

```
# /etc/pyfw/wishes.yaml

```