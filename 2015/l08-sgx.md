SGX and Haven
=============

Why are we reading this paper? **TODO:** Which paper? SGX or Haven?

 - Advanced hardware isolation mechanism
   + Last paper in our tour of isolation mechanisms
 - Strong threat model that is relevant in practice
   + Many desktops run malware
   + Malware may control complete OS
 - Uses cutting-edge technology (Intel SGX)
   + But, no deployed experience with SGX yet
   + May have design and implementation flaws
   + First hardware is available (see ref below)

SGX Goal
--------

 - Even when OS is compromised, app can still keep secrets
   + Maybe not whole OS compromised
   + But maybe attacker is running a key logger
 - Target applications:
   + Logging in to your bank
     * Secure: OS/Key logger cannot steal your password+PIN to login
   + Video/music player for copyrighted content (DRM)
     * Secure: OS cannot steal key to decrypt content

_Ambitious goal:_

 - App relies on OS
   + How to defend against a malicious OS?
 - OS interface is wide
   + How to check for app that OS behaves appropriately?
 - Much opportunity for "Iago" attacks
   + See paper "Iago Attacks: Why the System Call API is a Bad Untrusted RPC Interface" paper [here](iago) or on our [front page](../index.html).

_Iago attacks: attacks that untrusted OS can use to attack an application_

 - OS modifies `getpid()` and `time()` to return a different number, same number
   + `getpid()` and `time()` often used to seed a pseudo random generator
 - OS can confuse server running SSL
   + OS can record packets from a successful connection
   + OS can cause the next of instance of SSL to use same server nonce
     - By returning same value for `time()` and `getpid()` as for earlier connection
   + OS can replays packets
     * SSL server thinks it is a fresh connection, but it isn't
     * Maybe launch a man-in-the-middle attack
 - OS modifies `mmap()` to map a physical page that the OS controls over app stack
   + `malloc()` calls `mmap()`
   + OS can run arbitrary code
   + OS can read app secrets (e.g., private key of SSL connection)
 - **Lesson:** simple systems calls (e.g., getpid and time) can cause trouble
   - App must be written defensively
   - Protecting legacy apps against malicious OS seems hard

Much research on defending against malicious OS

 - Some use TPM or late boot
 - Some use a trusted hypervisor
 - Some use special processors
 - Little impact---mostly an intellectually-challenging exercise
 - Now Intel's Skylake includes **SGX** (see ref below)
   + It provides hardware mechanism to help defend against Iago attacks

SGX Threat model
----------------

 - Attacker controls OS
 - Attacker can observe traffic between processor and memory
   + Every component that is not the processor is untrusted
 - Intel is trusted
   + Chip works correctly
   + Private key isn't compromised
 - Side channels cannot be exploited

**SGX: Software Guard Extensions**

 - **Enclave:** trusted execution environment inside a process
   + Processor ensures that enclave memory isn't accessible to OS, BIOS, etc.
 - **Attestation**
   + Processor signs content of enclave with private key baked into chip
   + Verifier uses Intel's public key to check signature
 - **Sealing**
   + Scheme for sealing enclave on termination, and unsealing later
   + **TODO:** Do they mean sort of like "paging out" or stopping, saving to disk and later restoring it and continue running it?

### Enclave

 - Figure 1 in Haven paper
 - `ECREATE` creates an empty enclave
   + starting virtual address and size
 - _EPC:_ enclave page cache
   + Region in physical memory
   + Processor's memory encryption interface
     - encrypts/decrypts when writing/reading to/from EPC
     - Also integrity protected
   + `EADD` to add an EPC page to enclave
 - Processor maintains a map (_EPCM_) that for each EPC page records:
   + page type (REG, ...), the enclave ID, the virtual address for the page, and permissions
   + EPCM is accessible only to processor
   + Map is consulted on each enclave page access
     * Is the page in enclave mode?
     * Does page belong to enclave?
     * Is the page for the accessed virtual address?
     * Does access agree with page permissions?
 - Paging an EPC page to external storage
   + OS executes `EWD` to evict page into buffer
     * encrypted, version number, etc.
   + OS can write buffer to external storage
   + OS executes `ELDB` to load encrypted page into EPC
     * use version number to detect roll-back attacks

Starting enclave (`EXTEND`, `EINIT`):

 - Processor keeps a cryptographic log of how the enclave was built
   _ `EXTEND` adds 256-byte region to log
 - Log contains content (code, data, stack, heap), location of each page, security flags 
 - `EINIT` takes as argument a `SIGSTRUCT`
   + signed by a sealing authority (enclave writer)
   + includes: expected signed hash of enclave and public key of enclave owner
   + `EINIT` verifies signature and hash
   + Enclave identity stored in `SECS`

**Attestation:** Remote party can verify that enclave runs correct code

 - An enclave gets its keys use `EGETKEY`
   + keys for encrypting and sealing
 - `EREPORT` generates a signed report
   + Report contains the hash of log and a public key for enclave
     * public is in enclave-provided data in report?
   + This report can be communicated to another enclave
   + The receiving enclave can verify the report using the public key in the enclave
 - A _special Quoting enclave_ can create a signed "quote" using processor's private key
   + Uses a group signature key so that individual processors cannot be identified

Entering/exit enclave:

 - enter using ENTER with a thread control structure (TCS)
 - exit: EEXIT, interrupt, or exception
 - resume an enclave using ERESUME

Protected bank client (hypothetical and simplified)

 - **Goal:** Prevent OS from stealing user's password
 - Assume a secure path from keyboard to enclave (Intel ME?)
 - Client downloads bank application and runs it
 - Bank application creates enclaves with code+data
   + code includes reading from keyboard, SSL, etc.
   + generate a quote 
   + connect to server, setup secure channel (e.g., SSL), and send quote
 - Server verifies quote
   + server knows runs that client started with the right software
   + i.e. not some rogue client that maybe emails user password to adversary
 - Server sends challenge
   + client uses password to respond to challenge over SSL
   + password inside enclave, encrypted
   + OS cannot steal it
 - Server checks challenge

SGX security discussion
-----------------------

 - Difficult to evaluate security
   + processors with SGX just have become available
   + no experience with deployments
 - TCB
   + Processor
   + Fab of processor
   + Intel's private key
 - Iago attacks
   + Can OS read/write data inside enclave
     * Processor's EPC prevents this
   + Can OS remap memory?
     * Processor's EPCM prevent this attack
   + Can OS confuse application?
     * Client must be carefully written to rely on few OS functions
     * Client needs a reliable source of randomness to implement SSL
         - `RDRAND`
     * Client must be able to send and receive packets
         - check results
 - Side channel attacks
   + Excluded by threat model, but possible in practice
   + Hyperthreading
   + Shared L3 cache
   + Multi-socket

Haven
-----

 - Use SGX for executing unmodified Windows applications in the cloud securely
 - Securely means don't trust cloud provider
 - Haven is a research project

### Threat model

 - System admins control cloud software
 - Remote attackers may control cloud software
 - OS may launch "Iago" attacks
   + May pass arbitrary values to Haven
   + May interrupt execution of Haven
 - Hardware is implemented correctly
   + SGX is correct

### Plan: shielded execution

 - Run applications in cloud with security equivalent to running application on own hardware
   + Don't trust cloud software
 - Provide an application environment so that it can interact with untrusted software
   + Applications need to send packets
   + Applications need to store files
   + ...
   + Application needs operating systems
 - Challenge
   + How to implement OS on top of host OS while stilling being resistant to Iago attacks

Haven builds on two components

 - Intel SGX
 - Drawbridge
   + Small interface on top of which libOS implements Win32
   + Small interface protects host OS from application (similar to native client)
   + Haven protects application from host OS

### Haven design (figure 2)

 - Implement Drawbridge's API so that it protects against Iago attacks
 - Shield module implements API inside enclave
   + interacts with host OS using a narrow, untrusted API
   + untrusted API is a subset of drawbridge's API (see figure 3)
 - Untrusted runtime tunnels between Shield in enclave and host kernel
   + Also needed for bootstrap
 - Host kernel contains SGX driver and drawbridge host
   + drawbridge host implements the narrow API using OS calls

Shield services

 - Virtual memory
   + Enclave starts at 0 (to handle null pointer deferences by app, libos)
   + Tracking memory pages used by application/libos
   + Adding/removing memory pages from enclave
     * Verifies that changes have been made correctly
   + Never allows host to pick virtual-memory addresses
   + Doesn't allow application and libos to allocate pages outside of enclave
 - Storage
   + Final lab
 - Threads
   + user-level scheduling (e.g., so that mutexes work)
   + multiplexes threads on a fixed number of threads created at startup
     - Allocate a fixed number of TCSs at start
 - Misc
   + `RDRAND` for trusted source of randomness
   + No fork
   + No address space randomization

### Discussion

 - Can Haven run unmodified apps?
   + No fork--minor problem on Windows?
   + Cannot map an enclave page at several virtual addresses
     * Needed to modify applications
 - Security?
   + Fuzzing testing untrusted interface?

References
----------

 1. [Iago attacks][iago]
 2. [SGX Overview][sgx]
 3. [SGX Instructions Overview][sgxinstr]
 4. [SGX Hardware][sgxhw]
 5. [SGX Security Discussion][sgxsec]
 6. [Drawbridge][drawbridge]
 
 
[iago]: https://cseweb.ucsd.edu/~hovav/dist/iago.pdf "Iago attacks"
[sgx]: http://www.pdl.cmu.edu/SDI/2013/slides/rozas-SGX.pdf "SGX Overview"
[sgxinstr]: https://software.intel.com/sites/default/files/article/413936/hasp-2013-innovative-instructions-and-software-model-for-isolated-execution.pdf "SGX Instructions overview"
[sgxhw]: https://jbeekman.nl/blog/2015/10/sgx-hardware-first-look/ "SGX hardware"
[sgxsec]: https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2015/january/intel-software-guard-extensions-sgx-a-researchers-primer/ "SGX Security discussion"
[drawbridge]: http://research.microsoft.com/pubs/141071/asplos2011-drawbridge.pdf "Drawbridge"
