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
###### Sample 1
OCSP of provided certificate. Issuer is automagically determined
```
$ xray-ocsp --cert src/test/java/docgen/google.pem
ocsp server location from certificate AIA: http://ocsp.pki.goog/gts1o1
caIssuers location from certificate AIA : http://pki.goog/gsr2/GTS1O1.crt
ops: 
    OCSPRequest -> tbsRequest: 
            version: 0 (v1)
            requestList -> [1] -> reqCert: 
                        hashAlgorithm: 
                            algo: 1.3.14.3.2.26 (SHA1)
                            params: NULL
                        issuerNameHash: 42:46:30:c2:27:19:db:de:70:f0:8f:fc:73:e5:a6:5f:66:38:17:bc
                        issuerKeyHash: 98:d1:f8:6e:10:eb:cf:9b:ec:60:9f:18:90:1b:a0:eb:7d:09:fd:2b
                        serialNumber: 00:ed:7f:80:a1:37:93:02:56:08:00:00:00:00:19:0d:cd
            requestExtensions -> [1]: 
                    Id: 1.3.6.1.5.5.7.48.1.2 (OCSP Nonce Extension)
                    Critical: true
                    Value: b0:a7:d9:22:6b:14
    Http Request POST: 
    URL: http://ocsp.pki.goog/gts1o1
    ResponseCode: 200 (0xc8)
    OCSPResponse: 
        responseStatus: 0 (successful)
        responseBytes: 
            type: 1.3.6.1.5.5.7.48.1.1 (OCSP Basic Response)
            value: 
                tbsResponseData: 
                    version: 0 (v1, default)
                    responderID -> byKey: 98:d1:f8:6e:10:eb:cf:9b:ec:60:9f:18:90:1b:a0:eb:7d:09:fd:2b
                    producedAt: 2019-10-31T22:25:39Z
                    responses -> [0]: 
                            certID: 
                                hashAlgorithm: 
                                    algo: 1.3.14.3.2.26 (SHA1)
                                    params: NULL
                                issuerNameHash: 42:46:30:c2:27:19:db:de:70:f0:8f:fc:73:e5:a6:5f:66:38:17:bc
                                issuerKeyHash: 98:d1:f8:6e:10:eb:cf:9b:ec:60:9f:18:90:1b:a0:eb:7d:09:fd:2b
                                serialNumber: 00:ed:7f:80:a1:37:93:02:56:08:00:00:00:00:19:0d:cd
                            certStatus -> value: good
                signatureAlgorithm: 
                    algo: 1.2.840.113549.1.1.11 (sha256WithRSAEncryption)
                    params: NULL
                signature: 4e:fc:46:f8:e7:df:c4:9c:13:02:be:17:c6:e7:22:d4:01:34:31:11:4f:b5:59:fb:2c:67:f9:c9:f6:0c:6b:53:af:cd:00:c6:0d:29:39:c2:e9:59:a0:1d:37:9d:2d:69:
                           03:9c:f1:0d:7b:df:57:2f:cb:7a:e2:24:1d:4f:31:98:e9:01:16:4b:c7:b4:a3:af:5d:00:0e:08:90:c6:88:03:bd:d6:0e:74:f4:96:74:b1:5b:2a:8b:58:1a:1b:11:2b:
                           1f:2c:5a:58:dd:87:c2:d4:6a:94:00:a7:7b:ee:13:1f:3a:64:64:53:15:3c:98:37:ef:66:36:66:56:95:ca:2f:82:1d:c9:e7:cf:0b:94:68:8b:0d:19:32:d2:43:e7:9f:
                           ff:3f:35:05:84:c7:e6:a6:e5:a1:39:88:67:57:ff:90:80:98:cf:a2:aa:e6:a1:88:a5:52:c6:a7:72:59:4e:1b:09:36:42:42:9a:f5:ef:86:55:16:b2:71:ec:bd:e9:70:
                           91:76:09:3a:3c:18:de:75:85:04:dc:5b:ac:10:ec:e5:a2:79:c8:b6:06:dd:81:64:55:9a:09:f0:aa:2d:72:b3:92:00:44:29:93:f0:49:ea:ae:dc:b5:69:cc:34:be:1d:
                           20:6d:41:d8:da:0a:c4:48:3e:73:56:f6:73:a2:f7:c4

```
###### Sample 2
OCSP of provided TLS certificate of the Facebook site
```
$ xray-ocsp --cert tls:www.facebook.com
ocsp server location from certificate AIA: http://ocsp.digicert.com
caIssuers location from certificate AIA : http://cacerts.digicert.com/DigiCertSHA2HighAssuranceServerCA.crt
ops: 
    OCSPRequest -> tbsRequest: 
            version: 0 (v1)
            requestList -> [1] -> reqCert: 
                        hashAlgorithm: 
                            algo: 1.3.14.3.2.26 (SHA1)
                            params: NULL
                        issuerNameHash: cf:26:f5:18:fa:c9:7e:8f:8c:b3:42:e0:1c:2f:6a:10:9e:8e:5f:0a
                        issuerKeyHash: 51:68:ff:90:af:02:07:75:3c:cc:d9:65:64:62:a2:12:b8:59:72:3b
                        serialNumber: 05:29:0e:9b:be:17:be:ed:83:55:03:01:24:93:d0:ac
            requestExtensions -> [1]: 
                    Id: 1.3.6.1.5.5.7.48.1.2 (OCSP Nonce Extension)
                    Critical: true
                    Value: 11:ce:53:fa:0a:4d
    Http Request POST: 
    URL: http://ocsp.digicert.com
    ResponseCode: 200 (0xc8)
    OCSPResponse: 
        responseStatus: 0 (successful)
        responseBytes: 
            type: 1.3.6.1.5.5.7.48.1.1 (OCSP Basic Response)
            value: 
                tbsResponseData: 
                    version: 0 (v1, default)
                    responderID -> byKey: 51:68:ff:90:af:02:07:75:3c:cc:d9:65:64:62:a2:12:b8:59:72:3b
                    producedAt: 2019-10-31T12:21:34Z
                    responses -> [0]: 
                            certID: 
                                hashAlgorithm: 
                                    algo: 1.3.14.3.2.26 (SHA1)
                                    params: NULL
                                issuerNameHash: cf:26:f5:18:fa:c9:7e:8f:8c:b3:42:e0:1c:2f:6a:10:9e:8e:5f:0a
                                issuerKeyHash: 51:68:ff:90:af:02:07:75:3c:cc:d9:65:64:62:a2:12:b8:59:72:3b
                                serialNumber: 05:29:0e:9b:be:17:be:ed:83:55:03:01:24:93:d0:ac
                            certStatus -> value: good
                signatureAlgorithm: 
                    algo: 1.2.840.113549.1.1.11 (sha256WithRSAEncryption)
                    params: NULL
                signature: 74:61:f1:3a:bc:a4:06:0e:27:94:52:96:83:65:96:bb:e2:27:c2:a1:35:51:ec:8d:55:63:84:eb:5b:e4:b3:ed:bd:57:61:8d:03:48:9c:e7:45:a8:e5:7a:97:eb:a9:04:
                           9a:4e:db:68:7d:18:56:df:70:cc:14:5a:3c:af:ca:74:00:e6:1e:9f:8b:a7:fe:f2:3b:93:50:45:e6:78:22:b9:5e:98:43:47:d0:77:db:a5:1d:df:3d:85:94:55:4f:32:
                           8a:b3:91:08:71:38:8c:87:19:1b:61:5a:ee:02:19:62:ac:46:47:82:b0:66:49:18:6f:58:62:80:12:21:b2:9d:be:68:e3:90:5c:2f:a1:98:fa:01:58:71:5d:d9:80:d0:
                           16:7f:c2:4f:a0:9d:4d:ce:b3:e3:55:c4:02:7d:44:81:ac:8b:08:2e:0f:c5:f4:6b:b1:5e:13:3d:c0:cb:bb:b5:5b:75:45:fa:69:52:c7:cf:46:24:c2:d3:9f:78:32:12:
                           db:70:59:fc:a5:a4:9c:8f:d9:08:1e:ed:8c:cc:84:15:da:c9:50:57:88:f0:04:69:87:98:98:22:65:f1:86:07:c7:6e:ba:f3:43:83:06:d3:0a:76:2c:29:db:31:38:f1:
                           30:0b:e9:a7:51:e1:5a:c4:80:f8:88:22:5b:3d:c1:3d

```
###### Sample 3
OCSP via certificate serialnumber and issuer
```
$ xray-ocsp --issuer-cert http://pki.goog/gsr2/GTS1O1.crt --ocsp-server http://ocsp.pki.goog/gts1o1 --serial 0x00ed7f80a1379302560800000000190dcd
ops: 
    OCSPRequest -> tbsRequest: 
            version: 0 (v1)
            requestList -> [1] -> reqCert: 
                        hashAlgorithm: 
                            algo: 1.3.14.3.2.26 (SHA1)
                            params: NULL
                        issuerNameHash: 42:46:30:c2:27:19:db:de:70:f0:8f:fc:73:e5:a6:5f:66:38:17:bc
                        issuerKeyHash: 98:d1:f8:6e:10:eb:cf:9b:ec:60:9f:18:90:1b:a0:eb:7d:09:fd:2b
                        serialNumber: 00:ed:7f:80:a1:37:93:02:56:08:00:00:00:00:19:0d:cd
            requestExtensions -> [1]: 
                    Id: 1.3.6.1.5.5.7.48.1.2 (OCSP Nonce Extension)
                    Critical: true
                    Value: 7c:c9:a7:f5:bd:fe
    Http Request POST: 
    URL: http://ocsp.pki.goog/gts1o1
    ResponseCode: 200 (0xc8)
    OCSPResponse: 
        responseStatus: 0 (successful)
        responseBytes: 
            type: 1.3.6.1.5.5.7.48.1.1 (OCSP Basic Response)
            value: 
                tbsResponseData: 
                    version: 0 (v1, default)
                    responderID -> byKey: 98:d1:f8:6e:10:eb:cf:9b:ec:60:9f:18:90:1b:a0:eb:7d:09:fd:2b
                    producedAt: 2019-10-31T22:25:39Z
                    responses -> [0]: 
                            certID: 
                                hashAlgorithm: 
                                    algo: 1.3.14.3.2.26 (SHA1)
                                    params: NULL
                                issuerNameHash: 42:46:30:c2:27:19:db:de:70:f0:8f:fc:73:e5:a6:5f:66:38:17:bc
                                issuerKeyHash: 98:d1:f8:6e:10:eb:cf:9b:ec:60:9f:18:90:1b:a0:eb:7d:09:fd:2b
                                serialNumber: 00:ed:7f:80:a1:37:93:02:56:08:00:00:00:00:19:0d:cd
                            certStatus -> value: good
                signatureAlgorithm: 
                    algo: 1.2.840.113549.1.1.11 (sha256WithRSAEncryption)
                    params: NULL
                signature: 4e:fc:46:f8:e7:df:c4:9c:13:02:be:17:c6:e7:22:d4:01:34:31:11:4f:b5:59:fb:2c:67:f9:c9:f6:0c:6b:53:af:cd:00:c6:0d:29:39:c2:e9:59:a0:1d:37:9d:2d:69:
                           03:9c:f1:0d:7b:df:57:2f:cb:7a:e2:24:1d:4f:31:98:e9:01:16:4b:c7:b4:a3:af:5d:00:0e:08:90:c6:88:03:bd:d6:0e:74:f4:96:74:b1:5b:2a:8b:58:1a:1b:11:2b:
                           1f:2c:5a:58:dd:87:c2:d4:6a:94:00:a7:7b:ee:13:1f:3a:64:64:53:15:3c:98:37:ef:66:36:66:56:95:ca:2f:82:1d:c9:e7:cf:0b:94:68:8b:0d:19:32:d2:43:e7:9f:
                           ff:3f:35:05:84:c7:e6:a6:e5:a1:39:88:67:57:ff:90:80:98:cf:a2:aa:e6:a1:88:a5:52:c6:a7:72:59:4e:1b:09:36:42:42:9a:f5:ef:86:55:16:b2:71:ec:bd:e9:70:
                           91:76:09:3a:3c:18:de:75:85:04:dc:5b:ac:10:ec:e5:a2:79:c8:b6:06:dd:81:64:55:9a:09:f0:aa:2d:72:b3:92:00:44:29:93:f0:49:ea:ae:dc:b5:69:cc:34:be:1d:
                           20:6d:41:d8:da:0a:c4:48:3e:73:56:f6:73:a2:f7:c4

```
