gpg-agent
[![TravisCI](https://travis-ci.org/prep/gpg.svg?branch=master)](https://travis-ci.org/prep/gpg.svg?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/prep/gpg)](https://goreportcard.com/report/github.com/prep/gpg)
[![GoDoc](https://godoc.org/github.com/prep/gpg/agent?status.svg)](https://godoc.org/github.com/prep/gpg/agent)
=========
This is an experimental repository of a client to the GPG agent. It was built out of a desire to have a somewhat friendly interface to GPG keys stored on a smart card by way of GPG.

At this point, the interface might be subject to change.

Things to know
--------------
There are a couple things *off* about this Go package, namely:

* There is no way to know what *type* of key the GPG agent returns (signing, encryption or authentication), so in the case of subkeys the user has to make this distinction manually.
* It borrows code from `crypto/rsa`, because the interface of the `rsa` package expects a private key to be provided, which is not possible when the private key is stored on a smart card. Therefore, the relevant code from `crypto/rsa` was copied to an internal package in this repository where the `PrivateKey{}` was changed to add a `DecryptFunc` field that gets called instead of the unexported `decrypt()` function in the rsa package.

TODO
----
* There are possibly some unnecessary type conversions happening because `bufio.ReadString()` is used as opposed to `bufio.ReadBytes()`.
