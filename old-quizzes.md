Some questions may already be [here](http://css.csail.mit.edu/6.858/2014/quiz.html)

Quiz 2 2011
-----------

Q8: An "Occupy Northbridge" protestor has set up a Twitter
account to broadcast messages under an assumed name. In
order to remain anonymous, he decides to use Tor to log into
the account.  He installs Tor on his computer (from a
trusted source) and enables it, launches Firefox, types in
www.twitter.com into his browser, and proceeds to log in.
What adversaries may be able to now compromise the protestor
in some way as a result of him using Tor? Ignore security
bugs in the Tor client itself.

A8: The protestor is vulnerable to a malicious exit node
intercepting his non-HTTPS-protected connection. (Since Tor
involves explicitly proxying through an exit node, this is
easier than intercepting HTTP over the public internet.)


Q9: The protestor now uses the same Firefox browser to
connect to another web site that hosts a discussion forum,
also via Tor (but only after building a fresh Tor circuit).
His goal is to ensure that Twitter and the forum cannot
collude to determine that the same person accessed Twitter
and the forum. To avoid third-party tracking, he deletes all
cookies, HTML5 client-side storage, history, etc.  from his
browser between visits to different sites. How could an
adversary correlate his original visit to Twitter and his
visit to the forum, assuming no software bugs, and a large
volume of other traffic to both sites?

A9: An adversary can fingerprint the protestor's browser,
using the user-agent string, the plug-ins installed on that
browser, window dimensions, etc., which may be enough to
strongly correlate the two visits.

---

Quiz 2, 2012
------------

Q2: Alyssa wants to learn the identity of a hidden service
running on Tor. She plans to set up a malicious Tor OR, set
up a rendezvous point on that malicious Tor OR, and send
this rendezvous point's address to the introduction point of
the hidden service. Then, when the hidden service connects
to the malicious rendezvous point, the malicious Tor OR will
record where the connection is coming from.

Will Alyssa's plan work? Why or why not?

A2: Will not work. A new Tor circuit is constructed between
