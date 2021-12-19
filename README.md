# k-amon-k - Yet another log4j scanner
## Quick-n-Dirty installation
Assuming you have a *working* Go installation in your *NIX

* `git clone git@github.com:thanasisk/k-amon-k.git`
* `go get golang.org/x/sys/unix`
* `go build`
* `./k-amon-k foo.war`
---
Releases etc coming
## FAQ
---
- What's with the name?
- I really like this band, if you are into metal music, make sure to support [them](https://k-amon-k.bandcamp.com/)
---
- How does it work?
- At the time of writing, log4j 2.0.17 is considered the *only* safe version, thus the only good known SHA256. The utility contains known *BAD* SHA256s for known vulnerable versions.
---
- Does it support nested Zips/Jars etc?
- Yes!
---
- Is it not MD5, that "competing" implementations use,considered broken from a security perspective?
- Yes and indeed it is. While an attack is might not be practical, let's use SHA256.
---
- Where has this been tested on?
- Why, Linux only of course.
## License
GPL v3

