# gonss3

Package documentation: https://godoc.org/github.com/rusq/gonss3

Package gonss implements the subset of Mozilla NSS3 library. It implements
just enough to decrypt the firefox profile passwords.

I take no credit, implementation is entirely based on [this project][4] which
is based on [Dr Stephen Henson research for "Netscape Key Databases"][1].

Supports only `key4.db` and `json` format of login file, as everything else is
obsolete.

This library is created for educational purposes and licenced under LGPL 3.0.

## Usage
```go
package main
import "github.com/rusq/gonss3"

func main() {
  profile, err := gonss3.New("/path/to/profile", []byte("masterpass"))
  // handle err

  userCt, passCt := // fetch some data from logins.json

  user,err := profile.DecryptField(userCt)
  // handle err
  pass,err := profile.DecryptField(passCt)
  // handle err

  fmt.Println(user, pass)
}
```

## TODO
[ ] TESTS

## Useful links

* [Mozilla BPE chart][2]
* [PSWRecovery4Moz docs][3]

[1]: http://web.archive.org/web/20150212092002/http://www.drh-consultancy.demon.co.uk/key3.html
[2]: https://github.com/lclevy/firepwd/blob/f48522352c27c8d1868d7a3ad0f5e3da3b1b922d/mozilla_pbe.pdf
[3]: https://github.com/philsmd/pswRecovery4Moz/blob/master/pswRecovery4Moz.txt
[4]: https://github.com/lclevy/firepwd/