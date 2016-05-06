/*
tweetnacl-go is a port of Dan Bernstein's "crypto library in a 100 tweets" code to the Go language. 
It is implemented as a wrapper around the original code to preserve the design and timing
characteristics of the original implementation.

Version Info
------------
tweetnacl: 20140427

tweetnacl-go: 0.00.0

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
   [Passing zero length Go byte array to a C function][golang-nuts]). The conversion to a (\*C.uchar) pointer
   has been abstracted into a convenience function _makePtr_, which includes a commented out version
   that returns nil for a zero length array if you prefer not to use the esoteric 'unsafe' version.


References
----------

1.  http://tweetnacl.cr.yp.to
2.  http://tweetnacl.cr.yp.to/tweetnacl-20131229.pdf
3.  http://cr.yp.to/highspeed/naclcrypto-20090310.pdf
4.  http://blog.skylable.com/2014/05/tweetnacl-carrybit-bug
5.  http://cryptojedi.org/peter/data/tenerife-20130121.pdf
6.  http://coderinaworldofcode.blogspot.com/2014/03/on-nacl.html
7.  http://blog.regehr.org/archives/1063
8.  http://www.daemonology.net/blog/2014-09-04-how-to-zero-a-buffer.html
9.  http://www.daemonology.net/blog/2014-09-06-zeroing-buffers-is-insufficient.html
10. http://www.daemonology.net/blog/2014-09-05-erratum.html
11. https://github.com/keybase/go-tweetnacl
12. http://www.metzdowd.com/pipermail/cryptography/2016-March/028824.html
13. https://groups.google.com/forum/#!topic/golang-nuts/NNBdjztWquo

*/
package tweetnacl
