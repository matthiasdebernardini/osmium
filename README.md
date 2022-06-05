# Why

Osmium creates a string (thats easy to backup) and derives all your passwords from that. This is marginally better to having to store everything.

# Security

This app runs but its probably best to use BitWarden or 1Password as a password manager at the moment.

Currently there is no encryption, but you can use any encryption tool to encrypt the mnemonic seed which is stored at `$HOME/.config/osmium/mnemonic.backup` in plaintext.

This uses [https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki](BIP-85) method of deriving new entropy from existing entropy. BIP85 being [https://coldcard.com/docs/bip85](used in the wild).

When you run this program, it will emit logs in the directory it was ran in. These logs have all the internal data.

As mentioned during init, you have to backup the seed to (ideally) paper or some robust method or storage. Without this seed, you can not recover the passwords.

# Usage 

`$ osmium-pwm --init true --new # to get a new seed`

`$ osmium-pwm --init --new "1 github" # to make a new password`

Keep a table of the key-value pair that the `new` command uses to track your passwords.

You have to make the config directory yourself.
