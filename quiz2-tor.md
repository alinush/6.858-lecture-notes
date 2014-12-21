Tor
===
---
## Resources

  * [Paper](http://css.csail.mit.edu/6.858/2014/readings/tor-design.pdf)
  * Blog posts: [1](https://blog.torproject.org/blog/top-changes-tor-2004-design-paper-part-1), [2](https://blog.torproject.org/blog/top-changes-tor-2004-design-paper-part-2), [3](https://blog.torproject.org/blog/top-changes-tor-2004-design-paper-part-3)
  * [Lecture note from 2012](http://css.csail.mit.edu/6.858/2012/lec/l16-tor.txt)
  * [Old quizzes](http://css.csail.mit.edu/6.858/2014/quiz.html)

---

## Overview

 - Goals
 - Mechanisms
   * Streams/Circuits
   * Rendezvous Points & Hidden services
 - Directory Servers
 - Attacks & Defenses
 - Practice Problems

---

## Goals

 - Anonymous communication
 - Responder anonymity
   * If I run a service like "mylittleponey.com" I don't want anyone
     associating me with that service
 - Deployability / usability
   * Why a security goal? 
     + Because it increases the # of people using Tor, i.e. the _anonimity set_
       - ...which in turn increases security
         * (adversary has more people to distinguish you amongst)
 - TCP layer (Why? See explanations in lecture notes above)
 - **NOT** P2P (because more vulnerable?)

---

## Circuit creation

TODO: Define circuit

Alice multiplexes many TCP streams onto a few _circuits_. Why? Low-latency system, expensive to make new circuit.

TODO: Define Onion Router (OR)

_Directory server_: State of network, OR public keys, OR IPs

ORs:

 - All connected to one another with TLS
 - See blog post 1: Authorities vote on consensus directory document

Example:

    [ Draw example of Alice building a new circuit ]
    [ and connecting to Twitter.                   ]

---

## Rendezvous Points & Hidden services

Example: 

    [ Add an example of Alice connecting to Bob's  ]
    [ hidden service on Tor                        ]

Bob runs hidden service (HS): 

  - Decides on long term PK/SK pair
  - Publish introduction points, advertises on lookup service
  - Builds a circuit to _Intro Points_, waits for messages

Alice wants to connect to Bob's HS:

 - Build circuit to new _Rendezvous Point (RP)_ (any OR)
   * Gives _cookie_ to RP
 - Builds circuit to one of Bob's intro points and sends message
   * with `{RP, Cookie, g^x}_PK(Bob)`
 - Bob builds circuit to RP, sends `{ cookie, g^y, H(K)}`
 - RP connects Alice and Bob
