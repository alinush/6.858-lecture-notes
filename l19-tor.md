Tor
===

What's the goal of the paper (or Tor)?

 - Anonymity for clients, which want to connect to servers on the internet.
 - Anonymity for servers, which want to service requests from users.
 - What is anonymity?
   + Adversary cannot tell which users are communicating with which servers.
   + Adversary (most likely) knows that users, servers are communicating via Tor.
   + That is, Tor not designed to prevent adversary from finding Tor users.

How to achieve anonymity?

 - Must encrypt traffic to/from the person that wants to be anonymous.
   + Otherwise, adversary looks at packets and figures out what's going on.
 - But encryption is not enough: could still trace where encrypted packets went.
 - Mix one user's traffic with traffic from other users (or "cover traffic").
   + Anonymity for one user requires having many other users like the first one.
   + If all other users just run BitTorrent, then Wikipedia user is easy to spot.
   + If all other users use Firefox, then a Chrome user would be easy to spot.
   + ...
 - Adversary would not be able to tell which user initiated what connections.
 - The mixing component must change the packets (e.g., encrypt/decrypt).
   + Otherwise, can look for where the exact same packet shows up later.
 - So, approach: relay traffic via intermediary that encrypts/decrypts.

Why do we need more than one node?

 - Scalability: handle more traffic than a single node.
 - Compromise: attacker learns info about direct clients of compromised node.
   + With many indep. nodes, this affects only a small fraction of traffic.
   + With onion routing, attacker must compromise all nodes in the chain.
 - Traffic analysis: attacker can correlate incoming / outgoing traffic.
   + Can look at timing between packets, or volume of packets.
   + Chaining makes timing/volume analysis attack more difficult to mount.
 - Can attacker still succeed?
   + Yes, if they observe or compromise enough nodes.
   + For instance, may suffice to observe first and last node.
   + Attacker can also inject timing info (by delaying packets) to analyze.

Main idea: onion routing.

 - Mesh of onion routers (ORs) in the network.
 - Assumption: client knows public keys of all ORs.
 - Client picks some path through this network.
 - Naive strawman of onion routing (not quite Tor):
   + Client encrypts message in public key of each OR in path in turn.
   + Send message to first OR in path, which decrypts & relays, and so on.
   + "Exit node" (last OR in path) sends the data out into the real network.
 - Why is this a good design?
   + Each OR knows previous & next hop, not ultimate source or destination.
   + With two ORs, compromising a single OR does not break anonymity.

At what level should we relay things?

 - Could do any level -- IP packets, TCP connections, application-level (HTTP)
 - What's the advantage / disadvantage?
   + Lower-level (IP): more general, fewer app. changes, works with more apps.
   + Higher-level (TCP, HTTP): more efficient (overhead for a single TCP frame, rather than overhead for multiple IP frames that store a single TCP frame), more anonymous.
 - What does Tor do?
   + TCP-level relaying, using SOCKS (intercepts libc calls).
   + Examples of efficiency: no need for TCP flow-control, Tor does re-xmit
   + Examples of lost generality: UDP doesn't work, can't traceroute, ..
   + How does DNS work with Tor, if no UDP support?
     * SOCKS can capture the destination's hostname, not just IP address
     * Exit node performs DNS lookup, establishes TCP connection
 - Examples of anonymity that's lost at lower layers?
   + If we did IP, would leak lots of TCP info (seq#, timestamp)
   + If we did TCP, would leak all kinds of HTTP headers and cookies
   + If we did HTTP, can violate anonymity via Javascript, Flash, ..
     * Lots of identifiable features in Javascript environment.
     * Browser version, history sniffing, local network addrs/servers..
   + "Protocol normalization": fix all degrees of freedom in higher protocol.
     * Hard to do in practice; app-specific proxies are useful (e.g., Privoxy).
     * Demo of browser "identification": https://panopticlick.eff.org/

Tor design.

 - Mesh of ORs: every OR connected via SSL/TLS to every other OR.
   + Don't need CA-signed SSL/TLS certs.
   + Tor has its own public key checking plan using directory servers.
   + ORs mostly run by volunteers: e.g., MIT runs several.
 - End-users run an onion proxy (OP) that implements SOCKS.
 - OR has two public keys: identity key and onion key.
 - Identity key registered with directory, signs OR state.
 - Onion key used by OPs to connect to ORs, build circuits.
   + Client downloads list of ORs from directory.
   + Chooses a chain of ORs to form circuit, contacts each OR in turn.
 - Clients building circuits is expensive. - Why do it this way?
   + Any single server might be compromised, can't trust it.
   + Unavoidable to trust the client machine, however.
 - Why do we need an onion key in addition to an identity key?
   + Might be able to protect identity key from long-term compromises.
   + Each OR uses identity key to sign its current onion key.
 - Why does Tor need a directory?
   + Someone needs to approve ORs.
     * Otherwise attacker can create many ORs, monitor traffic.
   + Does having a directory compromise anonymity?
     * No, don't need to query it online.
   + What if a directory is compromised?
     * Clients require majority of directories to agree.
   + What if many directories are compromised?
     * Attacker can inject many ORs, monitor traffic.
   + What if directories are out-of-sync?
     * Attacker may narrow down user's identity based on dir info.
     * User that saw one set of directory messages will use certain ORs.

Terminology: circuits and streams.

 - Circuit: a path through a list of ORs that a client builds up.
   + Circuits exist for some period of time (perhaps a few minutes).
   + New circuits opened periodically to foil attacks.
 - Stream is effectively a TCP connection.
   + Many streams run over the same circuit (each with separate stream ID).
   + Streams are an important optimization: no need to rebuild circuit.
 - Why does Tor need circuits?
 - What goes wrong if we have long-lived circuits?
   + Adversary may correlate multiple streams in a single circuit.
   + Tie a single user's connections to different sites, break anonymity.

Tor circuits.

 - Circuit is a sequence of ORs, along with shared (symmetric AES) keys.
   + ORs `c_1, c_2, .., c_n`
   + Keys `k_1, k_2, .., k_n`
 - Cell format:
   + `+---------+---------------+-----------+`
   + `| Circuit | Control/Relay |  - DATA   |`
   + `+---------+---------------+-----------+`
   + `  2 bytes   +   1 byte   +  509 bytes `
 - Think of the "Circuit" and "Control/Relay" fields as link-layer headers.
   + Circuit IDs are per-link (between pairs of ORs).
   + Used to multiplex many circuits on the same TLS connection between ORs.
   + Control messages are "link-local": sent only to an immediate neighbor.
   + Relay messages are "end-to-end": relayed along the circuit.
 - Why is all traffic in fixed-size cells?
   + Makes traffic analysis harder.
 - What are control commands?
   + padding: keepalive or link padding.
   + create/created/destroy: creating and destroying circuits.
 - What are relay commands (what's in the DATA)?
   + If the relay packet is destined to the current node:
   + `+----------+--------+-----+-----+-----------+`
   + `| StreamID | Digest | Len | CMD | RelayData |`
   + `+----------+--------+-----+-----+-----------+`
   + ` 2 bytes   + 6 bytes+  2  +  1  + 498 bytes  `
   + If the relay packet is destined for another node:
   + `+-------------------------------------------+`
   + `| Encrypted, opaque data  +   +   +   +   + |`
   + `+-------------------------------------------+`
   + `   +    +    +    +    509 bytes             `
 - CMD field for TCP data is "relay data".
 - Other values like "relay begin", .. used to set up streams.

How does the OP send data via circuit?

 - Compose relay packet as above (not encrypted yet).
 - Compute a valid checksum (digest).
   + Digest is based on the target OR that should decrypt packet.
   + Hash is taken over some function of key + all msgs exchanged with that OR.
     * Prevents replay attacks and active attacks
   + First 2 bytes of digest are zeroes, other 4 bytes come from the hash.
 - Encrypt with `AES(k_n)`, then `AES(k_{n-1}), .., AES(k_1).`
 - Send encrypted cell to the first OR (`c_1`).
   + (Effectively reverse process for OP receiving data via circuit.)

What does an OR do with relay packets?

 - If it's coming from OP's direction, decrypt and forward away from OP
 - If it's coming not from OP's direction, encrypt and forward towards OP

How does an OR know if a relay packet is destined to it or not?

 - Verify checksum: if matches, most likely meant for the current OR.
 - Optimization: first 2 bytes of digest should be zero.
   + If the first two bytes are non-zero, can skip hashing: not our packet.
 - If checksum does not match, not meant for this OR, keep relaying.
 - Nice properties:
   + Packet size independent of path length.
   + Only the last OR knows the destination.

How to establish a new stream?

 - OP sends a "relay begin" via circuit. - Contains target hostname, port.
 - Who picks stream ID? - OP can choose arbitrary stream ID in its circuit.

What is the "leaky pipe" topology?

 - OP can send relay messages to any OR along its circuit (not just the last OR).
 - Can build stream (i.e., TCP connection) via any OR, to foil traffic analysis.

Initializing circuits.

 - OP picks the sequence of ORs to use for its circuit.
   + Why have the OP do this? - Resistance to other ORs "diverting" the circuit.
 - Connect to first OR, issue "create" operation to create circuit.
   + Create includes a DH key-exchange message.
   + Created response includes DH key-exchange reply.
 - Key exchange protocol:
   + [ OP, OR agree on prime p, generator g ]
   + OP chooses random x.
   + OP sends `E_{PK_OR}(g^x)`.
   + OR chooses random y.
   + OR computes `K=g^xy`.
   + OR replies with `g^y, H(K || "handshake")`.
   + OP computes `K=g^xy`.
 - How do we authenticate the parties here?
   + First DH message encrypted with OR's onion key.
   + Hash of key in DH response proves to client that correct OR decrypted msg.
   + Server does not authenticate client -- anonymity!
 - Forward secrecy: what? how?
 - Key freshness: why? how?
 - Who chooses the circuit ID?
   + The client end of the TLS connection (not the overall circuit's OP).
   + Each circuit has a different circuit ID for each link it traverses.
 - What's in the DATA for Control packets?
   + Control operations (create, destroy) or responses (e.g. created).
   + Arguments (e.g., DH key-exchange data).
 - For each subsequent OR, OP sends a "relay extend" message via circuit.
   + Include the same DH key-exchange message in the "relay extend" cell.
   + At the end of circuit, "relay extend" transforms into "create".
   + Client ends up with shared (symmetric AES) key for each OR in circuit.
 - Why does Tor have separate control cells vs relay cells?
   + Ensures cells are always fixed size.
   + Last OR in the old circuit needs to know the new OR & circuit IDs.

What state does each OR keep for each circuit that passes through it?

 - Circuit ID and neighbor OR for two directions in the circuit (to/from OP).
 - Shared key with OP for this circuit and this OR.
 - SHA-1 state for each circuit.

Can we avoid storing all of this state in the network?

 - Not without a variable-length path descriptor in each cell.
 - Exit node would likewise need a path descriptor to know how to send back.
 - Intermediate nodes would need to perform public-key crypto (expensive).

Why does Tor need exit policies?

 - Preventing abuse (e.g., anonymously sending spam).
 - Exit policies similar to firewall rules (e.g., cannot connect to port 25).
   + Each exit node checks the exit policy when new connection opened.
 - Why publish exit policy in directory, along with other node info?
   + Not used for enforcement.
   + OP needs to know what exit nodes are likely to work.

What if Tor didn't do integrity checking?

 - Need integrity to prevent a tagging attack.
 - Attacker compromises internal node, corrupts data packets.
 - Corrupted packets will eventually get sent out, can watch where they go.

How does Tor prevent replays?

 - Each checksum is actually checksum of all previous cells between OP & OR.
 - Checksum for same data sent again would be different.
 - Works well because underlying transport is reliable (SSL/TLS over TCP).

Anonymous services.

 - Hidden services named by public keys (pseudo-DNS name "publickey.onion").
 - Why the split between introduction and rendezvous point?
   + Avoid placing traffic load on introduction points.
   + Avoid introduction point transferring known-illegal data.
 - Split prevents both problems.
   + Bob (service) has an introduction point (IP).
   + Alice chooses a rendezvous point (RP), tells Bob's IP about RP.
   + Introduction point does not relay data.
   + Rendezvous point doesn't know what data it's relaying
 - Why does Bob connect back to Alice?
   + Admission control, spread load over many rendezvous points.
 - What's the rendezvous cookie? - Lets Bob prove to Alice's RP that it's Bob.
 - What's the authorization cookie?
   + Something that might compel Bob to reply, when he otherwise wouldn't.
   + Maybe a secret word most people don't know.
   + Limits DoS attacks on Bob's server (can just send many cookies).
   + Stored in hostname: cookie.pubkey.onion.
 - End state: two circuits to the RP, with a stream connected between them.
   + RP takes relay cells from one circuit's stream and
   +   sends them on a stream in the other circuit.
   + Bridged data is encrypted using key shared between Alice & Bob (DH).
   + Each can control their own level of anonymity.
   + Neither knows the full path of the other circuit.

Potential pitfalls when using Tor?

 - Application-level leaks (Javascript, HTTP headers, DNS, ..)
   + Use an app-level proxy (e.g., Privoxy strips many HTTP headers).
 - Fingerprinting based on Tor client behavior (how often new circuit opened).
 - Timing/volume analysis (partial defense is to run your own Tor OR).
 - Fingerprinting web sites: number of requests & file sizes of popular sites.
   + Quantization from fixed-size cells helps a bit.
 - Malicious ORs: join network, advertise lots of bandwidth, open exit policy.

Benefits / risks of running an OR?

Benefits:

 + more anonymity

Risks:

 - resource use
 - online attacks (DoS, break-ins, ..)
 - offline attacks (e.g., machine seized by law enforcement)

How hard is it to block Tor?

 - Find list of OR IPs from directory, block all traffic to them.
 - How to defend against such an attack?
 - Reveal different ORs to different clients?
   + Allows for client fingerprinting based on ORs used.
 - Maintain some unlisted ORs?
   + Want to use unlisted ORs only as the first hop, to avoid fingerprinting.
   + Tor has notion of "bridge" node, which is an unlisted OR.
 - How to find these unlisted "bridge" ORs?
   + Want legitimate user to find them, but not let adversary enumerate them.
   + Approach taken by Tor: special bridge directory.
   + Reveal 3 bridges to each IP (via HTTP) or email addr (via email).
   + Reveal new bridges to same client address only after 24 hours.
   + Can rate-limit by IP, find attempts to enumerate bridge database, etc.
   + For email, easier for adversary to create fake identities (email addrs).
   + Tor trusts 3 mail providers to rate-limit signup (gmail, yahoo, mit).

Would you use Tor? - What applications is it good for?

 - Might be too slow to use for all traffic (high latency).
 - But unfortunately that means only sensitive traffic would go via Tor.
 - Plausible attacks exist, so not great against very powerful adversaries.
 - Maybe a good way to avoid denial-of-service attacks (i.e., offload to Tor).
 - Allegedly, Google used Tor to check if servers special-case Google's IPs.

How active is Tor?

 - Much more active use now than what the paper describes.
   * ~3000 public ORs, ~1000 exit nodes, ~1000 bridge nodes, ~2GB/s OR bandwidth.
   * 8-9 (?) directory servers, ~1600 directory mirrors.
 - Hard problems: distributing entry point IPs, approving ORs, ..
 - Some BitTorrent use, but not overwhelming: mostly, too slow for large files.

Alternative approach: DC-nets ("Dining cryptographer networks").

 - N participants, but suppose there's only one sender (not known who).
 - Every pair of participants shares a secret bit.
 - To transmit a "0" bit, send XOR of all secrets. - Otherwise, send the opposite.
 - All transmissions are public: to recover bit, XOR everyone's transmissions.
 - Can build up to send multiple bits, use a collision-detection protocol, etc.
 - Costly in terms of performance, but provides much stronger security than Tor.
 - See the Dissent OSDI 2012 paper for more details on a DCnet-based system.

References:

 - https://metrics.torproject.org/
 - http://dannenberg.ccc.de/tor/status-vote/current/consensus
 - https://svn.torproject.org/svn/projects/design-paper/challenges.pdf
 - https://svn.torproject.org/svn/projects/design-paper/blocking.pdf
 - http://en.wikipedia.org/wiki/Dining_cryptographers_problem
 - http://dedis.cs.yale.edu/2010/anon/papers/osdi12.pdf

