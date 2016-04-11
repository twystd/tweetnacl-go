tweetnacl-golang: version 0.00.0 

# TweetNaCl - GO port

*tweetnacl-golang* is a port of Dan Bernstein's [TweetNaCl][tweetnacl] "crypto library in a 100 tweets" code
to the Go language. It is implemented as a wrapper around the original code to preserve the design and timing
characteristics of the original implementation.

Version Info
------------
tweetnacl: 20140427
tweetnacl-golang: (in progress)

Usage
-----


Building
--------


Disclaimer
----------
The Go wrapper has been kept as 'thin' as possible to avoid compromising the careful design
and coding of the original TweetNaCl implementation. However, cryptography being what it is, 
the wrapper may have (entirely inadvertently) introduced non-obvious vulnerabilities (for 
instance [How to zero a buffer][daemonology]). So ....

**USE ENTIRELY AT YOUR OWN RISK !**

Notes
-----
1. There is an existing port of TweetNaCl to Go ([go-tweetnacl][go-tweetnacl]) which reimplements the C code
   in Go.
2. The cgo FFI doesn't handle zero length byte arrays particularly elegantly (see discussion at
   [Passing zero length byte array to a C function][golang-nuts]) - the conversion to a (\*C.uchar) pointer
   has been abstracted into a convenience function _makePtr_. _makePtr_ includes a commented out version
   that returns nil for a zero length array if you prefer not to use the esoteric 'unsafe' version.

TODO
----
1. Handle zero length messages - will currently crash with a panic because unsafe.Pointer(&message[0]) does
   NOT hack it. 
2. Either add validation to byte array argument lengths or unit tests to check that it does fail when
   the supplied arguments are invalid.
3. Validate CryptoHash/CryptoHashBlocks against known SHA-512

References
----------

1.  [TweetNaCl][tweetnacl]
2.  [TweetNaCl: A crypto library in 100 tweets] [tweetnacl-pdf]
3.  [Cryptography in NaCl] [nacl-pdf]
4.  [TweetNaCl: How cr.yp.to’s developers got carried away by the carry bit][carrybitbug]
5.  [NaCl: Cryptography for the Internet][slides]
6.  [On NaCl: Undefined Behaviour][ciawof]
7.  [Safe, Efficient, and Portable Rotate in C/C++][regehr]
8.  [How to zero a buffer][daemonology]
9.  [Zeroing buffers is insufficient][daemonology2]
10. [How to zero a buffer: Erratum][daemonology3]
11. [go-tweetnacl][go-tweetnacl]
12. [On the Impending Crypto Monoculture][gutmann]
13. [Passing zero length byte array to a C function][golang-nuts]

[tweetnacl]:     http://tweetnacl.cr.yp.to
[tweetnacl-pdf]: http://tweetnacl.cr.yp.to/tweetnacl-20131229.pdf
[nacl-pdf]:      http://cr.yp.to/highspeed/naclcrypto-20090310.pdf
[carrybitbug]:   http://blog.skylable.com/2014/05/tweetnacl-carrybit-bug
[slides]:        http://cryptojedi.org/peter/data/tenerife-20130121.pdf
[ciawof]:        http://coderinaworldofcode.blogspot.com/2014/03/on-nacl.html
[regehr]:        http://blog.regehr.org/archives/1063
[daemonology]:   http://www.daemonology.net/blog/2014-09-04-how-to-zero-a-buffer.html
[daemonology2]:  http://www.daemonology.net/blog/2014-09-06-zeroing-buffers-is-insufficient.html
[daemonology3]:  http://www.daemonology.net/blog/2014-09-05-erratum.html
[go-tweetnacl]:  https://github.com/keybase/go-tweetnacl
[gutmann]:       http://www.metzdowd.com/pipermail/cryptography/2016-March/028824.html
[golang-nuts]:   https://groups.google.com/forum/#!topic/golang-nuts/NNBdjztWquo

