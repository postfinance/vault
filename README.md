[![Go Report Card](https://goreportcard.com/badge/github.com/postfinance/vault)](https://goreportcard.com/report/github.com/postfinance/vault)
[![GoDoc](https://godoc.org/github.com/postfinance/vault?status.svg)](https://godoc.org/github.com/postfinance/vault)
[![Build Status](https://travis-ci.org/postfinance/vault.svg?branch=master)](https://travis-ci.org/postfinance/vault)
[![Coverage Status](https://coveralls.io/repos/github/postfinance/vault/badge.svg?branch=master)](https://coveralls.io/github/postfinance/vault?branch=master)


# Package vault

Helper and wrapper functions for @hashicorp Vault.

## Package vault/kv

Functions to read, write and list secrets without worrying about the version of the KV engine.

### Requirements

Requires list and read privileges on `/sys/mounts`
