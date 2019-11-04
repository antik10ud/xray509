###### Usage
```
$ xray-tsq --help
xray-tsq 0.0.1
Usage: xray-tsq [-h] [--show-encodings] [--show-sourcenames]
                [--text-format-compact-lines] [-c=<mode>] [-f=<format>] SOURCE
Dump RFC 3161 Timestamp Query
      SOURCE                  Timestamp Query file or URL to process.
      --show-encodings        Show encodings
      --show-sourcenames      Show sourcenames, default to false
      --text-format-compact-lines
                              Specify output must compact single elements in
                                one line
  -c, --color=<mode>          Show colored output
                              The color parameter is optional (defaults to
                                `auto`)
                              The possible options are:
                               * auto - Only show colors if the platform
                                supports it.
                               * always - Turn on colored output.
                               * never - Turn off colored output.
                                Default: auto
  -f, --format=<format>       Specify output format
                              The format parameter is optional (defaults to
                                `text`)
                              The possible options are:
                               * text - Text output.
                               * json - JSON output.
                               * keys - KV output.
                               * csv - Comma Separated Values output.
                               * der - DER output (i.e. crt, cer)
                               * pem - PEM output.
                                Default: text
  -h, --help                  Displays this help message and quits.
```
###### Sample 1
Dump Timestamp Query
```
$ xray-tsq /tmp/ts.tsq
Version: 1 (0x1)
MessageImprint: 
    hashAlgorithm: 
        algo: 2.16.840.1.101.3.4.2.1 (SHA256)
        params: NULL
    hashedMessage: 3a:6e:b0:79:0f:39:ac:87:c9:4f:38:56:b2:dd:2c:5d:
                   11:0e:68:11:60:22:61:a9:a9:23:d3:bb:23:ad:c8:b7
Nonce: 553169931604925178 (0x7ad411f39bd1afa)
Include certs: true

```
