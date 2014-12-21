Web security
============

Web security for a long time meant looking at what the server was doing, since the client-side was very simple. On the server, CGI scripts were executed and they interfaced with DBs, etc.

These days, browsers are very complicated:

 * JavaScript: pages execute client-side code
 * The Document Object Model (DOM) 
 * XMLHttpRequests: a way for JavaScript client-side code to fetch content from the web-server asynchronously
    - a.k.a AJAX
 * Web Sockets
 * Multimedia support (the `<video>` tag)
 * Geolocation (webpages can determine physically where you are)
 * Native Client, for Google Chrome

For web-security, this means we're screwed: huge attack surface (See Figure 1)

    likelihood
    of correct
    ness
    ^
    |--\
    |   --\                --- we are here
    |      --\            /
    |         \          /
    |          \      <--
    |           -----*----
    |----------------------->
      # of features

Problems of composition: many layers

One problem with the web is the _parsing contexts_ problem
    
    <script>var = "UNTRUSTED CONTENT FROM USER";</script>

If the _untrusted_ content had a quote in it, perhaps the attacker could modify the code into:

    <script>var = "UNTRUSTED CONTENT"</script> 
    <script> /* bad stuff from attacker here */ </script>

Web specifications are long, tedios, boring, inconsistent, the size of the EU consistution (CSS, HTML) => they are vague aspirational documents that are never implemented.

This lecture we'll focus on client-side web-security.

Desktop applications come from a single principal (Microsoft, Google, etc)
Web applications come from a bunch of principals.

`http://foo.com/index.html` (see Figure 2)

 * Can analytics code access the facebook frame content?
 * Can analytics code interact with the text inputs? Can it declare event handlers?
 * What's the relationship beteen the Facebook frame (https) and the foo.com frame (http)?

To answer these questions browsers use a security model called the _same origin policy_

*Goal:* Two websites should not be able to tamper with each other, unless they want to.

Defining what _tampering_ means has gotten more complicated since the web first started.

*Strategy:* Each _resource_ is assigned an origin. JS code (a resource itself) can only access resources from its own origin.

What is an origin? An origin is a network protocol scheme + hostname + port. 
Example: 

 * `https://facebook.com:8181`
 * `http://foo.com/index.html`, implicit port 80
 * `https://foo.com/index.html`, implicit port 443

Loosely speaking, you can think of an origin as an UID in UNIX, with a frame being a _process_.

Four ideas in implementation of origins:

 1. Each origin has client side resources
     * Cookies, to implement state across different HTTP requests
     * DOM storage, a fairly new interface, a key-value store
     * A JavaScript namespace, defines what functions and interface are available to the origin (like the String class)
     * The DOM tree: a JavaScript reflection of the HTML in a page

                  [  HTML ]     
                  /       \     
            [ HEAD ]     [ BODY ]

     * A visual display area
 2. Each frame gets the origin of its URL 
 3. Scripts execute with the authority of their frame origin
 4. Passive content (images, CSS files) gets **zero** authority from the browser
    * Content sniffing attacks

Going back to our example: 

 * Google analytics and jQuery can do all sorts of stuff on the foo.com frame
 * The Facebook frame's inline JS cannot do anything to the foo.com frame
   - but it can talk to the foo.com frame using the `postMessage()` API
 * The JS code in the FB frame cannot issue an AJAX request to the foo.com webserver

MIME types: text/html. All version of IE in the past would look at the first 256 bytes of an object and ignore the `Content-Type` header. As a result, IE would misinterpret the type of files (due to bugs). Attacker can put JS code in a .jpg file. IE coerces it into text/html and then executes the JS code in the page.

Frames and window objects
-------------------------
Frames represent these sort of separate JS universes

A frame, w.r.t. to JS is an instance of a DOM node. Frames and window objects in JS point to each other. The window object acts like a namespace via which you can access any variable `x`.

Frames get the origin of the frame's URL `OR` a suffix of the original domain name.

`x.y.z.com` can say "I want to set my origin to" `y.z.com` by assigning `document.domain` to `y.z.com`. This only works (or should) with suffixes of `x.y.z.com`. So it cannot do `document.domain = a.y.z.com`. Also, cannot set `document.domain = .com` because the site would be able to impact cookies in any .com website.

Browsers distinguish between frames that assigned a value to document.domain and frames that did not.

Two frames can access each if:

 1. Both frames set `document.domain` to the same value
 2. Neither of the frames has changed `document.domain` and both values match

You have `x.y.z.com` (buggy or evil) trying to attack `y.z.com`, by shortening its domain. The browser will not allow this because y.z.com will have NOT changed its document.domain while x.y.z.com has.

DOM nodes
---------

Cookies
-------
Cookies have a _domain_ and a _path_.

    *.mit.edu/6.858

If path is `/` then all paths in the domain have access to the cookie.

On the client side there's `document.cookie`.

Cookies have a `secure flag` which means HTTP content should not be able to access that cookie.

When the browser generates a request, it's going to include all the matching cookies in that request (ambient authority).

How can different frames access other frames' cookies? If other frames can write cookies for other frames, then an attacker could log the victim into the attacker's gmail account and possibly read emails sent by the user.

Should `foo.co.uk` be allowed to set a cookie for `co.uk`? https://publicsuffix.org contains a list of all the top-level domains so that browsers do not allow cooking setting for domains like `co.uk`.

XMLHttpRequest
--------------
By default JS can only generate an AJAX request if it's going to its origin.

There's a new paradigm called Cross Origin Request S. (CORS), where the server can use an ACL to allow other domains to access it. Server returns a header `Access-Control-Allow-Origin: foo.com` to indicate foo.com is allowed.

Images, CSS
------
A frame can load images from any origin it desires but it cannot actually inspect the bits. But it can infer the size of the image via the placement of other nodes in the DOM. 

Same for CSS.

JavaScript
----------
If you do a cross-origin fetch of JS, that is allowed, but the frame cannot look at the source code. But the JS architecture kind of lets you because you can call the `toString` method on any public function `f`. The frame can also ask the web-server to fetch the JS for it and send it.

JS code is often obfuscated.

Plugins
-------
Java, Flash.

A frame can run a plugin from any origin. HTML5 might make them obsolete.

Cross Site Request Forgery (CSRF)
---------------------------------
An attacker can setup a page and embed a frame with the following source in it:
    
    http://bank.com/xfer?amount=500&to=attacker

The frame is set to be of size zero (invisible), Then the attacker gets the user to visit the page. Thus, he can steal money from the user.

This is because the URL can be guessed and is not random.

Solution: add some randomness to the URL.

The server can generate a random token and embed it in the "Transfer Money" page sent to the user.

    <form action="/transfer.cgi" ...>
        <input type="hiddne" name="csrf" value="a72fedb2129985bdc">

Now the attacker has to guess the token.

Network addresses
-----------------
A frame can send HTTP and HTTPS requests to a host that matches its origin. The security of the same origin policy is tied to DNS security. Because origin names are DNS names, DNS rebinding attacks can work against you.

Goal: Run attacker controlled JS with the authority of some victim website `victim.com`

Approach:  

  1. Register a domain name `attacker.com`
  2. Attacker sets up a DNS server to respond to requests for `*.attacker.com`
  3. Attacker gets user to visit `*.attacker.com`
  4. Browser generates a DNS request to `attacker.com`
  5. Attacker response has a small time-to-live (TTL)
  6. Meanwhile, the attacker configures the DNS server to bind `attacker.com` name to `victim.com`'s IP address
  7. Now if the user asks for a DNS resolution on attacker.com, he gets an address of victim.com
  8. The loaded attacker.com website wants to fetch a new object via AJAX. This request will now go to victim.com
    * Bad because attacker.com website just issued an AJAX request outside its origin.

How can you fix this? 

 * Modify your DNS resolver to check that outside domains are not resolved to internal addresses.
 * Enforce TTL to be 30 minutes

Pixels
------
Each frame gets its own bounding box and can draw wherever it wants there. Specifically, a parent frame can draw over a child frame (see Figure 3).

Solutions:  
 1. Use frame busting code (JS to figure out if you've been put in a frame by someone else)

  ```
  if (self != top)  
      alert("I'm a child frame, so won't load")  
  ```  
 2. Web server can send an HTTP response header called `X-Frame-Options` which tells the browser to not allow anyone to put its content into a frame.

Naming issues
-------------
`c` in ASCII versus `c` in Cyrillic allows attacker to register a `cats.com` domain that immitates the real `cats.com`

Plugins
-------
Subtle incompatibilites with the rest of the browser.

Java assumes different hostnames with the same IP address have the same origin (deviation from the SOP policy)

x.y.com will be in the same origin as z.y.com if they share the same IP address.

HTML5 screen sharing
--------------------
If you have a page that have multiple frames, a frame can take a screenshot of the entire browser.

