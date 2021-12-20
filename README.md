# pasmoco
**Don't use this for anything serious; incomplete as of yet**

This is a simple password manager for GNU/Linux, inspired in part by
[pass](https://www.passwordstore.org/).

Similarities to `pass` include striving for simplicity, being lightweight, as well as having
readable code, allowing for ease of maintenance. However, `pasmoco` differs from it, by

- Storing passwords differently. It stores each password in a separate file, along with metadata,
but filenames are random, and an encrypted index file is used to point the user to the correct
password. This was already done in [pwd.sh](https://github.com/drduh/pwd.sh)

- Being written in C99. 

- Delegating all encryption to Monocypher, rather than attempting to talk to GPG. Why is this? 

# Functionality
For now, I've only thought of making it do five things,

- Creating the directory where passwords are stored and corresponding index file, which defaults to
`$HOME/.local/share/pasmoco`, but the directory path can be set through the environment variable
PASMOCO_DIR

- Adding passwords to the directory. Each password will have metadata associated to it stored in the
file too, with a format taken after KeePass, storing title, username, password, URL and notes about
the service

- Listing all passwords

- Removing password entries

- Retrieving a password. At first, there will only be the option of printing it to stdout, but when
this program is far along enough, I plan on piping it directly to clipboard, by making use of xclip
in X11 and wl-clipboard in Wayland

# Motivation
I disliked some things `pass` does, such as

- Storing each password in an encrypted file, where the file name is supposed to be the name of the
service it's for. This means that anyone with read access to your filesystem can know at a glance
which services you use. To most other people, it's not really relevant metadata that needs to be
hidden, since it's not *that* critical to their security. But it seems the developer somewhat intends
the file name to be the service name, so I wanted to try making something with more paranoid defaults.

- Donenfeld claims `pass` doesn't have as much bloat as other password managers. While that might be
true (I have no idea, haven't taken a look at its source, but since it doesn't do much, I assume it
probably doesn't) `pass` needs Bash, and Bash *is* bloat, to me and to other people. As this is
written in C, obviously this doesn't depend on a particular shell.

- I honestly don't think that a password manager needs to deal with any sort of synchronization
between systems. Even if said synchronization is mostly delegated to a separate program, as many
things in pass are.

About the first point, I know that is covered by [pass-tomb](https://github.com/roddhjav/pass-tomb),
but that is not exactly default behaviour, it requires another separate program (which looks
promising actually), and the cherry on top is that it requires systemd. Since I've already said Bash
is bloat, I believe you can guess correctly what's my opinion on systemd, so let's not get into
that.

About the second point, I'm aware there's [tpm](https://github.com/nmeum/tpm/), as well as
[spm](https://notabug.org/kl3/spm/), and a myriad other small/smaller password managers written in
various scripting languages. Most of them, however, have the same "flawed" defaults, in the way I
described in the first point.

My reasons to start writing my own password manager are rather nitpicky, I'll admit that much. I can
definitely work around what I percieve to be wrong with these. But, I wanted to learn C through practice,
by writing a useful program.

# Compilation & Installation
Run-time dependencies are glibc and Monocypher for now, working with additional C standard library
implementations is planned.

Compile-time dependencies are GCC, Make, glibc, and Monocypher. Make sure you install header files
for glibc and Monocypher, if your distribution packages these files separately.

To get the source and compile it, do this in your shell,

```
$ git clone https://github.com/galcerte/pasmoco
$ cd pasmoco
$ make
```

and to install, run this as root,

```
# make install
```

You also might want to remove the binary that is generated,

```
$ make clean
```

# License
Code I've written myself is licensed under AGPL v3 as can be seen on the repo. This program uses
glibc, which is licensed under GPL v3, and Monocypher, licensed under either CC0-1.0 or 2-clause
BSD.
