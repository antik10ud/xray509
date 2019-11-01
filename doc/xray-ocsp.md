###### Usage
```
$ xray-ocsp --help
Usage: <main class> [-h] [--all] [--dump-checked-cert]
                    [--dump-checked-issuer-cert] [--nonce] [--show-encodings]
                    [--show-sourcenames] [--text-format-compact-lines]
                    [--use-get] [--cert=<cert>] [--issuer-cert=<issuerCert>]
                    [--ocsp-server=<ocspServer>]
                    [--requestor-name=<requestorName>] [--serial=<serial>]
                    [-a=<hashAlgo>] [-c=<mode>] [-f=<format>]
                    [-o=<outputFileBase>]
      --all                   Process all available OCSPs in source certificate
      --cert=<cert>           Issuer certificate, we'll try to obtain it from
                                AIA when not specified
      --dump-checked-cert     Dump checked certificate
      --dump-checked-issuer-cert
                              Dump checked issuer certificate
      --issuer-cert=<issuerCert>
                              Issuer certificate, we'll try to obtain it from
                                AIA when not specified
      --nonce                 Use OCSP nonce extension
      --ocsp-server=<ocspServer>
                              OCSP Server URL, we'll try to take it from
                                certificate AIA when not specified
      --requestor-name=<requestorName>
                              Requestor name
      --serial=<serial>       Serial of certificate to check
      --show-encodings        Show encodings
      --show-sourcenames      Show sourcenames, default to false
      --text-format-compact-lines
                              Specify output must compact single elements in
                                one line
      --use-get               Use OCSP GET request
  -a, --algo=<hashAlgo>       CertId hash algo
  -c, --color=<mode>          Show colored output
                              The color parameter is optional (defaults to
                                `auto`)
                              The possible options are:
                               * auto - Only show colors if the platform
                                supports it.
                               * always - Turn on colored output.
                               * never - Turn off colored output.
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
  -h, --help                  Displays this help message and quits.
  -o, --output-filename-base=<outputFileBase>
                              OCSP file output base (it'll generate .ors and .
                                orq files if specified)
```
![Example](xray-ocsp.svg)
###### Sample 1
OCSP of provided certificate. Issuer is automagically determined
```
$ xray-ocsp --cert src/test/java/docgen/google.pem
ocsp server location from certificate AIA: http://ocsp.pki.goog/gts1o1
caIssuers location from certificate AIA : http://pki.goog/gsr2/GTS1O1.crt
ops: 
    OCSPRequest -> tbsRequest: 
            version: 0 (0x0) (v1)
            requestList -> [1] -> reqCert: 
                        hashAlgorithm: 
                            algo: 1.3.14.3.2.26 (SHA1)
                            params: NULL
                        issuerNameHash: 42:46:30:c2:27:19:db:de:70:f0:8f:fc:73:e5:a6:5f:
                                        66:38:17:bc
                        issuerKeyHash: 98:d1:f8:6e:10:eb:cf:9b:ec:60:9f:18:90:1b:a0:eb:
                                       7d:09:fd:2b
                        serialNumber: 00:ed:7f:80:a1:37:93:02:56:08:00:00:00:00:19:0d:
                                      cd
            requestExtensions -> [1]: 
                    Id: 1.3.6.1.5.5.7.48.1.2 (OCSP Nonce Extension)
                    Critical: true
                    Value: e7:d5:f1:68:83:53
    Http Request POST: 
    URL: http://ocsp.pki.goog/gts1o1
    ResponseCode: 200 (0xc8)
    OCSPResponse: 
        responseStatus: 0 (0x0) (successful)
        responseBytes: 
            type: 1.3.6.1.5.5.7.48.1.1 (OCSP Basic Response)
            value: 
                tbsResponseData: 
                    version: 0 (0x0) (v1, default)
                    responderID -> byKey: 98:d1:f8:6e:10:eb:cf:9b:ec:60:9f:18:90:1b:a0:eb:
                                          7d:09:fd:2b
                    producedAt: 2019-11-01T06:36:20Z
                    responses -> [0]: 
                            certID: 
                                hashAlgorithm: 
                                    algo: 1.3.14.3.2.26 (SHA1)
                                    params: NULL
                                issuerNameHash: 42:46:30:c2:27:19:db:de:70:f0:8f:fc:73:e5:a6:5f:
                                                66:38:17:bc
                                issuerKeyHash: 98:d1:f8:6e:10:eb:cf:9b:ec:60:9f:18:90:1b:a0:eb:
                                               7d:09:fd:2b
                                serialNumber: 00:ed:7f:80:a1:37:93:02:56:08:00:00:00:00:19:0d:
                                              cd
                            certStatus -> value: good
                signatureAlgorithm: 
                    algo: 1.2.840.113549.1.1.11 (sha256WithRSAEncryption)
                    params: NULL
                signature: 2e:37:68:5d:3f:27:36:bd:a0:38:d3:1d:8c:a1:20:a3:
                           c9:7a:dc:a6:d1:02:73:da:a3:5a:3a:bf:11:9a:f8:98:
                           1d:46:c8:0d:1d:30:92:37:ea:10:4f:c0:c5:71:be:89:
                           6c:b6:c3:0f:70:c5:22:ac:5f:32:37:b1:5c:08:82:d7:
                           fb:85:95:4a:c8:9d:09:df:58:34:4e:9b:18:18:65:ba:
                           9a:24:4c:9d:46:b7:29:cb:02:6f:44:96:ea:78:46:ba:
                           63:ad:9f:b2:e6:1e:a5:13:84:a6:e8:7c:20:54:8d:75:
                           fe:8f:97:38:fc:23:ed:d1:ed:eb:32:c3:a0:f7:80:7c:
                           e6:59:78:55:c6:3f:4f:e1:ff:ca:3a:2c:1f:4d:59:0d:
                           bf:9a:fe:f6:8c:0e:db:68:e9:32:61:26:5c:3d:48:7f:
                           36:85:b4:1a:70:07:f2:97:a1:1c:8a:29:32:df:ee:e1:
                           20:ce:e3:07:07:66:13:05:45:89:21:ed:56:d6:ca:9e:
                           e1:eb:59:b2:61:5c:10:36:06:3d:e3:11:22:c4:b4:a2:
                           44:7b:9f:37:b0:c9:80:04:de:49:67:ea:ca:55:de:2e:
                           ab:45:25:05:f3:62:46:b5:b5:9b:92:e5:ed:e3:db:4d:
                           af:95:18:83:9a:d2:bf:6e:84:fa:f8:9f:2f:aa:7a:9d

```
###### Sample 2
OCSP of provided TLS certificate of the Facebook site
```
$ xray-ocsp --cert tls:www.facebook.com
ocsp server location from certificate AIA: http://ocsp.digicert.com
caIssuers location from certificate AIA : http://cacerts.digicert.com/DigiCertSHA2HighAssuranceServerCA.crt
ops: 
    OCSPRequest -> tbsRequest: 
            version: 0 (0x0) (v1)
            requestList -> [1] -> reqCert: 
                        hashAlgorithm: 
                            algo: 1.3.14.3.2.26 (SHA1)
                            params: NULL
                        issuerNameHash: cf:26:f5:18:fa:c9:7e:8f:8c:b3:42:e0:1c:2f:6a:10:
                                        9e:8e:5f:0a
                        issuerKeyHash: 51:68:ff:90:af:02:07:75:3c:cc:d9:65:64:62:a2:12:
                                       b8:59:72:3b
                        serialNumber: 05:29:0e:9b:be:17:be:ed:83:55:03:01:24:93:d0:ac
            requestExtensions -> [1]: 
                    Id: 1.3.6.1.5.5.7.48.1.2 (OCSP Nonce Extension)
                    Critical: true
                    Value: d4:ba:5b:c3:68:0f
    Http Request POST: 
    URL: http://ocsp.digicert.com
    ResponseCode: 200 (0xc8)
    OCSPResponse: 
        responseStatus: 0 (0x0) (successful)
        responseBytes: 
            type: 1.3.6.1.5.5.7.48.1.1 (OCSP Basic Response)
            value: 
                tbsResponseData: 
                    version: 0 (0x0) (v1, default)
                    responderID -> byKey: 51:68:ff:90:af:02:07:75:3c:cc:d9:65:64:62:a2:12:
                                          b8:59:72:3b
                    producedAt: 2019-11-01T12:21:38Z
                    responses -> [0]: 
                            certID: 
                                hashAlgorithm: 
                                    algo: 1.3.14.3.2.26 (SHA1)
                                    params: NULL
                                issuerNameHash: cf:26:f5:18:fa:c9:7e:8f:8c:b3:42:e0:1c:2f:6a:10:
                                                9e:8e:5f:0a
                                issuerKeyHash: 51:68:ff:90:af:02:07:75:3c:cc:d9:65:64:62:a2:12:
                                               b8:59:72:3b
                                serialNumber: 05:29:0e:9b:be:17:be:ed:83:55:03:01:24:93:d0:ac
                            certStatus -> value: good
                signatureAlgorithm: 
                    algo: 1.2.840.113549.1.1.11 (sha256WithRSAEncryption)
                    params: NULL
                signature: 72:2c:35:3e:40:2d:fb:ad:1a:37:24:df:56:6a:54:0a:
                           45:f9:2e:0a:d6:e2:86:6f:dc:6f:00:d5:1b:5b:5b:bc:
                           81:62:8d:1b:40:a3:31:a4:61:99:3c:70:85:6d:16:58:
                           34:e5:95:0f:89:ff:25:28:dd:6c:4b:50:1a:b3:b1:74:
                           94:f2:f0:4a:70:a2:53:f3:93:49:2a:19:3c:6e:fb:4b:
                           97:d8:5b:fa:80:63:5c:ca:b0:e5:1c:ee:d0:3e:d6:7c:
                           e7:89:ea:fd:cc:94:83:09:f1:6f:06:e1:14:2a:c2:96:
                           22:50:d4:d3:6a:b4:e5:fd:f1:db:a2:32:18:ff:2a:6d:
                           e6:f1:87:8b:2c:1f:dd:58:bf:f8:83:ed:06:fa:25:83:
                           0b:69:b3:f2:90:ab:75:46:e8:8e:f3:a9:bf:43:81:24:
                           28:18:f0:c6:de:8b:dd:ec:b8:c8:61:28:34:05:cf:5e:
                           65:c1:45:5f:4b:03:78:05:08:20:9c:3d:3c:c8:cb:30:
                           3e:97:65:0b:ed:93:30:46:8a:80:9c:bc:e5:47:d8:4b:
                           21:1a:42:9a:0f:d9:f6:ab:aa:e5:1f:c4:25:fa:6e:23:
                           78:fd:f0:a1:58:b7:33:56:ea:96:32:82:66:3e:37:3a:
                           bc:0b:e0:7a:54:20:75:e4:ea:a9:38:89:e2:56:4f:81

```
###### Sample 3
OCSP via certificate serialnumber and issuer
```
$ xray-ocsp --issuer-cert http://pki.goog/gsr2/GTS1O1.crt --ocsp-server http://ocsp.pki.goog/gts1o1 --serial 0x00ed7f80a1379302560800000000190dcd
ops: 
    OCSPRequest -> tbsRequest: 
            version: 0 (0x0) (v1)
            requestList -> [1] -> reqCert: 
                        hashAlgorithm: 
                            algo: 1.3.14.3.2.26 (SHA1)
                            params: NULL
                        issuerNameHash: 42:46:30:c2:27:19:db:de:70:f0:8f:fc:73:e5:a6:5f:
                                        66:38:17:bc
                        issuerKeyHash: 98:d1:f8:6e:10:eb:cf:9b:ec:60:9f:18:90:1b:a0:eb:
                                       7d:09:fd:2b
                        serialNumber: 00:ed:7f:80:a1:37:93:02:56:08:00:00:00:00:19:0d:
                                      cd
            requestExtensions -> [1]: 
                    Id: 1.3.6.1.5.5.7.48.1.2 (OCSP Nonce Extension)
                    Critical: true
                    Value: 55:bf:97:be:3a:8a
    Http Request POST: 
    URL: http://ocsp.pki.goog/gts1o1
    ResponseCode: 200 (0xc8)
    OCSPResponse: 
        responseStatus: 0 (0x0) (successful)
        responseBytes: 
            type: 1.3.6.1.5.5.7.48.1.1 (OCSP Basic Response)
            value: 
                tbsResponseData: 
                    version: 0 (0x0) (v1, default)
                    responderID -> byKey: 98:d1:f8:6e:10:eb:cf:9b:ec:60:9f:18:90:1b:a0:eb:
                                          7d:09:fd:2b
                    producedAt: 2019-11-01T06:36:20Z
                    responses -> [0]: 
                            certID: 
                                hashAlgorithm: 
                                    algo: 1.3.14.3.2.26 (SHA1)
                                    params: NULL
                                issuerNameHash: 42:46:30:c2:27:19:db:de:70:f0:8f:fc:73:e5:a6:5f:
                                                66:38:17:bc
                                issuerKeyHash: 98:d1:f8:6e:10:eb:cf:9b:ec:60:9f:18:90:1b:a0:eb:
                                               7d:09:fd:2b
                                serialNumber: 00:ed:7f:80:a1:37:93:02:56:08:00:00:00:00:19:0d:
                                              cd
                            certStatus -> value: good
                signatureAlgorithm: 
                    algo: 1.2.840.113549.1.1.11 (sha256WithRSAEncryption)
                    params: NULL
                signature: 2e:37:68:5d:3f:27:36:bd:a0:38:d3:1d:8c:a1:20:a3:
                           c9:7a:dc:a6:d1:02:73:da:a3:5a:3a:bf:11:9a:f8:98:
                           1d:46:c8:0d:1d:30:92:37:ea:10:4f:c0:c5:71:be:89:
                           6c:b6:c3:0f:70:c5:22:ac:5f:32:37:b1:5c:08:82:d7:
                           fb:85:95:4a:c8:9d:09:df:58:34:4e:9b:18:18:65:ba:
                           9a:24:4c:9d:46:b7:29:cb:02:6f:44:96:ea:78:46:ba:
                           63:ad:9f:b2:e6:1e:a5:13:84:a6:e8:7c:20:54:8d:75:
                           fe:8f:97:38:fc:23:ed:d1:ed:eb:32:c3:a0:f7:80:7c:
                           e6:59:78:55:c6:3f:4f:e1:ff:ca:3a:2c:1f:4d:59:0d:
                           bf:9a:fe:f6:8c:0e:db:68:e9:32:61:26:5c:3d:48:7f:
                           36:85:b4:1a:70:07:f2:97:a1:1c:8a:29:32:df:ee:e1:
                           20:ce:e3:07:07:66:13:05:45:89:21:ed:56:d6:ca:9e:
                           e1:eb:59:b2:61:5c:10:36:06:3d:e3:11:22:c4:b4:a2:
                           44:7b:9f:37:b0:c9:80:04:de:49:67:ea:ca:55:de:2e:
                           ab:45:25:05:f3:62:46:b5:b5:9b:92:e5:ed:e3:db:4d:
                           af:95:18:83:9a:d2:bf:6e:84:fa:f8:9f:2f:aa:7a:9d

```
