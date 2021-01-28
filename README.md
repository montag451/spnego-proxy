# Description #

Say that you work for a company that limits internet access through a
proxy which requires SPNEGO authentication, if you want to use an
application that does not support this authentication mechanism, then
you are out of luck. `spnego-proxy` enables these applications to
access internet by handling the authentication on behalf of the
client. It sits between the application and the real proxy and acts as
a normal HTTP proxy. It forwards requests made by the client to the
real proxy by adding a `Proxy-Authorization` header to the
requests. It does not alter nor does it inspects traffic between the
client and the real proxy.

# Installation #

Just copy one of the pre-compiled binary available
[here](https://github.com/montag451/spnego-proxy/releases/latest) on
your machine (preferably in a location contained in your PATH) and you
are done. If you feel adventurous or you don't like using binaries not
compiled by you, you can compile the binary from sources. To do so,
you need to install the [Go toolchain](https://golang.org/dl/). Once
the go toolchain is installed on your machine, execute `go get -u
github.com/montag451/spnego-proxy`. The binary will be installed in
the `bin` directory of your `GOPATH` (use `go env GOPATH` to find out
the value of `GOPATH` on your machine)

# Usage #

Type `spnego-proxy -h` to find out the options that the
command understands. The required options are:

- `addr`
- `config`
- `user`
- `realm`
- `proxy`

The `addr` flag specifies the listening address of the proxy.

The `config` flag specifies the location of a file which contains
Active Directory or Kerberos configuration information required to
authenticate with SPNEGO. The format of the file is specified
[here](https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/krb5_conf.html).

The `user` flag specifies the user name used to authenticate with the real proxy.

The `realm` flag specifies the Kerberos realm or the Active Directory
domain to which the user belongs.

The `proxy` flag specifies the address of the real proxy.
