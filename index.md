Computer systems security notes (6.858, Fall 2014)
==================================================

Lecture notes from 6.858, taught by [Prof. Nickolai Zeldovich](http://people.csail.mit.edu/nickolai/) and [Prof. James Mickens](http://research.microsoft.com/en-us/people/mickens/) in 2014. These lecture notes are slightly modified from the ones posted on the 6.858 [course website](http://css.csail.mit.edu/6.858/2014/schedule.html).

 * Lecture **1**: [Introduction](l01-intro.html): what is security, what's the point, no perfect security, policy, threat models, assumptions, mechanism, buffer overflows
 * Lecture **2**: [Control hijacking attacks](l02-baggy.html): buffer overflows, stack canaries, bounds checking, electric fences, fat pointers, shadow data structure, Jones & Kelly, baggy bounds checking
 * Lecture **3**: [More baggy bounds and return oriented programming](l03-brop.html): costs of bounds checking, non-executable memory, address-space layout randomization (ASLR), return-oriented programming (ROP), stack reading, blind ROP, gadgets
 * Lecture **4**: [OKWS](l04-okws.html): privilege separation, Linux discretionary access control (DAC), UIDs, GIDs, setuid/setgid, file descriptors, processes, the Apache webserver, chroot jails, remote procedure calls (RPC)
 * Lecture **5**: _Guest lecture_ on _penetration testing_ by Paul Youn, iSEC Partners
 * Lecture **6**: [Capsicum](l06-capsicum.html): confused deputy problem, ambient authority, capabilities, sandboxing, discretionary access control (DAC), mandatory access control (MAC), Capsicum
 * Lecture **7**: [Native Client (NaCl)](l07-nacl.html): sandboxing x86 native code, software fault isolation, reliable disassembly, x86 segmentation
 * Lecture **8**: [Web Security, Part I](l08-web-security.html): modern web browsers, same-origin policy, frames, DOM nodes, cookies, cross-site request forgery (CSRF) attacks, DNS rebinding attacks, browser plugins
 * Lecture **9**: [Web Security, Part II](l09-web-defenses.html): cross-site scripting (XSS) attacks, XSS defenses, SQL injection atacks, Django, session management, cookies, HTML5 local storage, HTTP protocol ambiguities, covert channels
 * Lecture **10**: _Guest lecture_ on _symbolic execution_ by Prof. Armando Solar-Lezama, MIT CSAIL
 * Lecture **11**: _Guest lecture_ on _Ur/Web_ by Prof. Adam Chlipala, MIT, CSAIL
 * Lecture **12**: [TCP/IP security](l12-tcpip.html): threat model, sequence numbers and attacks, connection hijacking attacks, SYN flooding, bandwidth amplification attacks, routing
 * Lecture **13**: [Kerberos](l13-kerberos.html): Kerberos architecture and trust model, tickets, authenticators, ticket granting servers, password-changing, replication, network attacks, forward secrecy
 * Lecture **14**: [ForceHTTPS](l14-forcehttps.html): certificates, HTTPS, Online Certificate Status Protocol (OCSP), ForceHTTPS
 * Lecture **15**: _Guest lecture_ on _medical software_ by Prof. Kevin Fu, U. Michigan
 * Lecture **16**: [Timing attacks](l16-timing-attacks.html): side-channel attacks, RSA encryption, RSA implementation, modular exponentiation, Chinese remainder theorem (CRT), repeated squaring, Montgomery representation, Karatsuba multiplication, RSA blinding, other timing attacks
 * Lecture **19**: _Guest lecture_ on _Tor_ by Nick Mathewson, Tor Project
   + 6.858 notes from 2012 on [Anonymous communication](l19-tor.html): onion routing, Tor design, Tor circuits, Tor streams, Tor hidden services, blocking Tor, dining cryptographers networks (DC-nets)

<!--
 * Lecture **17**: [User authentication](l17-authentication.html): what you have, what you know, what you are
 * Lecture **18**: [Private browsing](l18-priv-browsing.html): private browsing modes
 * Lecture **20**: [Mobile phone security](l20-android.html): Android
 * Lecture **21**: [Information flow tracking](l21-taintdroid.html): TaintDroid
 * Lecture **22**: _Guest lecture_ on _MIT's IS&T_ by Mark Silis and David LaPorte
 * Lecture **23**: [Security economics](l23-click-trajectories.html): spam value chain
-->
