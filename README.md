##siv-rb

This gem implements the SIV mode of operation for deterministic authenticated encryption, as described in [Rogaway, 2007](http://www.cs.ucdavis.edu/~rogaway/papers/siv.pdf) and standardized in [RFC 5297](http://tools.ietf.org/html/rfc5297). The underlying cipher is written as a low-level C extension on top of OpenSSL, for speed and compatibility.

SIV takes a key, a plaintext, and multiple variable-length octet strings that will be authenticated but not encrypted.  It produces a ciphertext having the same length as the plaintext and a synthetic initialization vector. If the same key, plaintext, and associated data are supplied to this function multiple times, the output is guaranteed to be identical. As per RFC 5297 section 3, you may use this function for nonce-based authenticated encryption by passing a nonce as the last associated data element.
  
###Usage

```ruby
require 'siv-rb'

cipher = SIV::Cipher.new(key)
enc = cipher.encrypt(plaintext, [ad1, ad2, ...])
dec = cipher.decrypt(enc, [ad1, ad2, ...])
```

###Details

The algorithm relies on the Cipher-based Message Authentication Code (CMAC), as standardized in [RFC 4493](http://tools.ietf.org/rfc/rfc4493.txt), as well as a slightly modified version of AES-CTR. The pseudo-code below, taken from the original paper on SIV, illustrates the algorithm in further detail:

![algorithm pseudo-code](http://i.imgbox.com/cbTmyL8D.png)

###License

This program is released under the GNU Affero General Public License.