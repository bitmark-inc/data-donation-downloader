# Data Donation Downloader

A downloader for data donation

## Installation

For mac user, you can install the tool via [homebrew](https://brew.sh/). Open your terminal, and run the following commands to install the tool.

```
/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
brew tap bitmark-inc/tools
brew install data-donation-downloader
```

## Basic Usage

* account: the bitmark account number
* network: determine which network you are going to use. default: live. (devel, test, live)
* init: initialze an account, register its encryption key to network
* version: show program version

```
data-donation-downloader -network <netowrk> -account <bitmark_account> [-init] [-version]
```

## User Story

As an researcher, you first need to generate a bitmark account. It is an 32 bytes hex string. For example,
`163AF34B27EFD39B2F6BA6724B124533D4E86D529E2644464AEFD6D1468C1EDD`. After you have an account, register it
with the following command:

```
data-donation-downloader -account 163AF34B27EFD39B2F6BA6724B124533D4E86D529E2644464AEFD6D1468C1EDD -init
```

You will see the results:
```
INFO[2017-09-06T17:41:52+08:00] Network:
INFO[2017-09-06T17:41:52+08:00] Auth Account: aRdg4X5KiZpiudcuxbTC4R3rensmnC7acUhtYpfDAAnRPddHKE
INFO[2017-09-06T17:41:52+08:00] Enc Public Key: A8F15C3EA4D2E63C0B0669F80844CFE2557DFFDB90E3A461AA1845DF5B02E776
INFO[2017-09-06T17:41:52+08:00] Check the encryption key here:  https://api.bitmark.com/v1/encryption_keys/aRdg4X5KiZpiudcuxbTC4R3rensmnC7acUhtYpfDAAnRPddHKE
INFO[2017-09-06T17:41:52+08:00] account registered
```

From now, any donor data send to your account number (in this example:  `aRdg4X5KiZpiudcuxbTC4R3rensmnC7acUhtYpfDAAnRPddHKE`) can be downloaded by this command:

```
$ data-donation-downloader -account 163AF34B27EFD39B2F6BA6724B124533D4E86D529E2644464AEFD6D1468C1EDD
```
