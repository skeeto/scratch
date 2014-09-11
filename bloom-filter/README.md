# Private Gmail Leak Tester

This project packs the leaked email database into a [bloom
filter](http://en.wikipedia.org/wiki/Bloom_filter) for safe, private
offline address testing against a list of leaked email addresses. The
filter is 4MB uncompressed and contains no actual e-mail addresses. It has
a false positive rate of less than 4%.

(Update in 2021: This is for historical preservation. I would not write a
bloom filter this way anymore, but it does capture some lessons learned.)
