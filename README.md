# Why

Osmium creates a string (thats easy to backup) and derives all your passwords from that. This is marginally better to having to store everything.

# Security

This app runs (and is overengineered) but its probably best to use BitWarden or 1Password as a password manager at the moment.

Currently there is no encryption, but you can use any encryption tool to encrypt the mnemonic seed which is stored at `$HOME/.config/osmium/mnemonic.backup` in plaintext.

This uses [BIP-85](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki) method of deriving new entropy from existing entropy. BIP85 being [used in the wild](https://coldcard.com/docs/bip85).

When you run this program, it will emit logs in the directory it was ran in. These logs have all the internal data.

As mentioned during init, you have to backup the seed (ideally) to paper or some robust method or storage. Without this seed, you can not recover the passwords.

# Usage 

`$ osmium-pwm --init true --new # to get a new seed`

`$ osmium-pwm --init --new "1 github" # to make a new password`

Keep a table of the key-value pair that the `new` command uses to track your passwords.

You have to make the config directory yourself.
