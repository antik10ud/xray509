###### Usage
```
$ xray-ts --help
xray-ts 0.0.1
Usage: xray-ts [-ChNX] [--dump] [--show-encodings] [--show-sourcenames]
               [--text-format-compact-lines] [--check-profile=<checkProfile>]
               [-a=<hashAlgo>] [-c=<mode>] [-E=<inputText>] [-f=<format>]
               [-F=<inputFile>] [-i=<messageImprint>] [-n=<nonce>]
               [-o=<outputFileBase>] [-p=<reqPolicy>] <tsa>
Analyze a RFC 3161 Timestamp
      <tsa>                   TimeStamp Server Authority URL
      --check-profile=<checkProfile>
                              Check response against specified profile
                                Default: null
      --dump                  Dump provided timestamp issuer cert
      --show-encodings        Show encodings
      --show-sourcenames      Show sourcenames, default to false
      --text-format-compact-lines
                              Specify output must compact single elements in
                                one line
  -a, --algo=<hashAlgo>       Message imprint hash algo
                                Default: SHA2_256
  -c, --color=<mode>          Show colored output
                              The color parameter is optional (defaults to
                                `auto`)
                              The possible options are:
                               * auto - Only show colors if the platform
                                supports it.
                               * always - Turn on colored output.
                               * never - Turn off colored output.
                                Default: auto
  -C, --cert-path             Require certificates
  -E, --source-text=<inputText>
                              Input text to hash
                                Default: null
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
  -F, --source-file=<inputFile>
                              Input file to hash
                                Default: null
  -h, --help                  Displays this help message and quits.
  -i, --imprint=<messageImprint>
                              Hexadecimal value as message imprint
                                Default: null
  -n, --nonce=<nonce>         Long value as nonce (64 bit)
                                Default: null
  -N, --nonce-random          Use random nonce
  -o, --output-filename-base=<outputFileBase>
                              Timestamp file output base (it'll generate .tsr
                                and .tsq files if specified)
                                Default: null
  -p, --policy=<reqPolicy>    Request policy
                                Default: null
  -X, --allow-invalid-imprint-len
                              Allow invalid imprint hash len for algo
```
###### Sample 1
Generate a new digital timestamp of the text 'data' and view the request, response and provided timestamp issuer cert chain. Save the request and response at /tmp/ts
```
$ xray-ts --cert-path --dump -o /tmp/ts --source-text data http://tsa.belgium.be/connect
TimeStampReq: 
    Version: 1 (0x1)
    MessageImprint: 
        hashAlgorithm: 
            algo: 2.16.840.1.101.3.4.2.1 (SHA256)
            params: NULL
        hashedMessage: 3a:6e:b0:79:0f:39:ac:87:c9:4f:38:56:b2:dd:2c:5d:11:0e:68:11:60:22:61:a9:a9:23:d3:bb:23:ad:c8:b7
    Nonce: 18391439387561831228 (0xff3b84ae53c02b3c)
    Include certs: true
response -> Http Request POST: 
        URL: http://tsa.belgium.be/connect
        ResponseCode: 200 (0xc8)
TimeStampResp: 
    Status: 
        status -> 0 (0x0): granted
        statusString
    TimeStampToken: 
        ContentType: 1.2.840.113549.1.7.2 (signedData)
        Content: 
            version: 3 (0x3)
            digestAlgorithms -> [0]: 1.3.14.3.2.26 (SHA1)
            encapContentInfo: 
                eContentType: 1.2.840.113549.1.9.16.1.4 (id-ct-TSTInfo)
                eContent: 
                    version: 1 (0x1)
                    policy: 2.16.56.9.3.1 (Belgium)
                    messageImprint: 
                        hashAlgorithm: 
                            algo: 2.16.840.1.101.3.4.2.1 (SHA256)
                            params: NULL
                        messageImprint: 3a:6e:b0:79:0f:39:ac:87:c9:4f:38:56:b2:dd:2c:5d:11:0e:68:11:60:22:61:a9:a9:23:d3:bb:23:ad:c8:b7
                    serialNumber: 19481435626292535 (0x45364332384537)
                    genTime: 2019-11-01T11:39:35Z
                    nonce: 18391439387561831228 (0xff3b84ae53c02b3c)
                    tsa -> directoryName: 
                            [0] -> 2.5.4.6 (countryName): BE (type: printableString)
                            [1] -> 2.5.4.5 (serialNumber): 2017 (type: printableString)
                            [2] -> 2.5.4.10 (organizationName): Belgium Federal Government (type: printableString)
                            [3] -> 2.5.4.3 (commonName): Time Stamping Authority (type: printableString)
            certificates: 
                0 (0x0): 
                    Version: v3
                    SerialNumber: 33554617 (hex: 0x20000b9, bits: 32)
                    Signature: 
                        algo: 1.2.840.113549.1.1.5 (SHA1withRSA)
                        params: NULL
                    Issuer: 
                        [0] -> 2.5.4.6 (countryName): IE (type: printableString)
                        [1] -> 2.5.4.10 (organizationName): Baltimore (type: printableString)
                        [2] -> 2.5.4.11 (organizationalUnitName): CyberTrust (type: printableString)
                        [3] -> 2.5.4.3 (commonName): Baltimore CyberTrust Root (type: printableString)
                    Subject: 
                        [0] -> 2.5.4.6 (countryName): IE (type: printableString)
                        [1] -> 2.5.4.10 (organizationName): Baltimore (type: printableString)
                        [2] -> 2.5.4.11 (organizationalUnitName): CyberTrust (type: printableString)
                        [3] -> 2.5.4.3 (commonName): Baltimore CyberTrust Root (type: printableString)
                    Validity: 
                        Duration: 25 years 13 minutes (synthetic)
                        NotBefore: 2000-05-12T18:46Z
                        NotAfter: 2025-05-12T23:59Z
                    SubjectPublicKeyInfo: 
                        Algorithm: 1.2.840.113549.1.1.1 (RSA)
                        modulus: 00:a3:04:bb:22:ab:98:3d:57:e8:26:72:9a:b5:79:d4:29:e2:e1:e8:95:80:b1:b0:e3:5b:8e:2b:29:9a:64:df:a1:5d:ed:b0:09:05:6d:db:28:2e:ce:62:a2:62:fe:b4:
                                 88:da:12:eb:38:eb:21:9d:c0:41:2b:01:52:7b:88:77:d3:1c:8f:c7:ba:b9:88:b5:6a:09:e7:73:e8:11:40:a7:d1:cc:ca:62:8d:2d:e5:8f:0b:a6:50:d2:a8:50:c3:28:
                                 ea:f5:ab:25:87:8a:9a:96:1c:a9:67:b8:3f:0c:d5:f7:f9:52:13:2f:c2:1b:d5:70:70:f0:8f:c0:12:ca:06:cb:9a:e1:d9:ca:33:7a:77:d6:f8:ec:b9:f1:68:44:42:48:
                                 13:d2:c0:c2:a4:ae:5e:60:fe:b6:a6:05:fc:b4:dd:07:59:02:d4:59:18:98:63:f5:a5:63:e0:90:0c:7d:5d:b2:06:7a:f3:85:ea:eb:d4:03:ae:5e:84:3e:5f:ff:15:ed:
                                 69:bc:f9:39:36:72:75:cf:77:52:4d:f3:c9:90:2c:b9:3d:e5:c9:23:53:3f:1f:24:98:21:5c:07:99:29:bd:c6:3a:ec:e7:6e:86:3a:6b:97:74:63:33:bd:68:18:31:f0:
                                 78:8d:76:bf:fc:9e:8e:5d:2a:86:a7:4d:90:dc:27:1a:39
                        publicExponent: 01:00:01
                        Key length: 2048 (0x800)
                        SHA1: e5:9d:59:30:82:47:58:cc:ac:fa:08:54:36:86:7b:3a:b5:04:4d:f0 (synthetic)
                        SHA2-256: a6:7f:e2:a9:af:96:7c:b5:bf:fd:c9:eb:da:8f:1a:b5:ea:bc:a2:54:f1:03:96:52:77:fd:4b:a3:3e:27:a1:87 (synthetic)
                        SHA3-256: 7f:ae:99:d7:30:6e:0e:04:88:95:dc:4d:9c:aa:2a:b7:6e:7d:59:2d:ee:99:67:93:14:8a:e9:48:26:3a:9c:2d (synthetic)
                    Extensions: 
                        [0] -> 2.5.29.14 (Subject key identifier) -> Value: e5:9d:59:30:82:47:58:cc:ac:fa:08:54:36:86:7b:3a:b5:04:4d:f0
                        [1] -> 2.5.29.19 (Basic constraints, critical): 
                                CA: true
                                pathLenConstraint: 3 (0x3)
                        [2] -> 2.5.29.15 (Key usage, critical): 
                                5 (0x5): KeyCertSign
                                6 (0x6): CRLSign
                    Fingerprints: 
                        MD5: ac:b6:94:a5:9c:17:e0:d7:91:52:9b:b1:97:06:a6:e4 (synthetic)
                        SHA1: d4:de:20:d0:5e:66:fc:53:fe:1a:50:88:2c:78:db:28:52:ca:e4:74 (synthetic)
                        SHA2-256: 16:af:57:a9:f6:76:b0:ab:12:60:95:aa:5e:ba:de:f2:2a:b3:11:19:d6:44:ac:95:cd:4b:93:db:f3:f2:6a:eb (synthetic)
                        SHA3-256: 8f:8d:88:30:41:3b:86:26:fa:09:50:dd:01:c7:ea:ff:a3:df:de:90:39:02:14:97:70:df:8f:89:8b:30:39:f0 (synthetic)
                    Security: 
                        CVE-2008-0166 (Openssl predictable random number generator): NotAffected (synthetic)
                        CVE-2017-15361 (ROCA: Vulnerable RSA generation): NotAffected (synthetic)
                1 (0x1): 
                    Version: v3
                    SerialNumber: 120009509 (hex: 0x7273325, bits: 32)
                    Signature: 
                        algo: 1.2.840.113549.1.1.5 (SHA1withRSA)
                        params: NULL
                    Issuer: 
                        [0] -> 2.5.4.6 (countryName): IE (type: printableString)
                        [1] -> 2.5.4.10 (organizationName): Baltimore (type: printableString)
                        [2] -> 2.5.4.11 (organizationalUnitName): CyberTrust (type: printableString)
                        [3] -> 2.5.4.3 (commonName): Baltimore CyberTrust Root (type: printableString)
                    Subject: 
                        [0] -> 2.5.4.10 (organizationName): Cybertrust, Inc (type: printableString)
                        [1] -> 2.5.4.3 (commonName): Cybertrust Global Root (type: printableString)
                    Validity: 
                        Duration: 10 years 59 minutes 14 seconds (synthetic)
                        NotBefore: 2010-08-18T19:11:52Z
                        NotAfter: 2020-08-18T19:11:06Z
                    SubjectPublicKeyInfo: 
                        Algorithm: 1.2.840.113549.1.1.1 (RSA)
                        modulus: 00:f8:c8:bc:bd:14:50:66:13:ff:f0:d3:79:ec:23:f2:b7:1a:c7:8e:85:f1:12:73:a6:19:aa:10:db:9c:a2:65:74:5a:77:3e:51:7d:56:f6:dc:23:b6:d4:ed:5f:58:b1:
                                 37:4d:d5:49:0e:6e:f5:6a:87:d6:d2:8c:d2:27:c6:e2:ff:36:9f:98:65:a0:13:4e:c6:2a:64:9b:d5:90:12:cf:14:06:f4:3b:e3:d4:28:be:e8:0e:f8:ab:4e:48:94:6d:
                                 8e:95:31:10:5c:ed:a2:2d:bd:d5:3a:6d:b2:1c:bb:60:c0:46:4b:01:f5:49:ae:7e:46:8a:d0:74:8d:a1:0c:02:ce:ee:fc:e7:8f:b8:6b:66:f3:7f:44:00:bf:66:25:14:
                                 2b:dd:10:30:1d:07:96:3f:4d:f6:6b:b8:8f:b7:7b:0c:a5:38:eb:de:47:db:d5:5d:39:fc:88:a7:f3:d7:2a:74:f1:e8:5a:a2:3b:9f:50:ba:a6:8c:45:35:c2:50:65:95:
                                 dc:63:82:ef:dd:bf:77:4d:9c:62:c9:63:73:16:d0:29:0f:49:a9:48:f0:b3:aa:b7:6c:c5:a7:30:39:40:5d:ae:c4:e2:5d:26:53:f0:ce:1c:23:08:61:a8:94:19:ba:04:
                                 62:40:ec:1f:38:70:77:12:06:71:a7:30:18:5d:25:27:a5
                        publicExponent: 01:00:01
                        Key length: 2048 (0x800)
                        SHA1: b6:08:7b:0d:7a:cc:ac:20:4c:86:56:32:5e:cf:ab:6e:85:2d:70:57 (synthetic)
                        SHA2-256: 65:1b:0a:df:67:4e:11:06:30:2a:51:a9:af:a2:14:e2:13:8e:88:77:3e:1a:f3:f6:62:02:8d:ab:63:72:8e:cf (synthetic)
                        SHA3-256: 30:c4:10:b5:63:36:fe:25:28:0a:b8:85:4d:d9:93:ad:ef:2a:12:4b:bb:3c:cb:43:da:ae:fb:ed:af:3a:bf:98 (synthetic)
                    Extensions: 
                        [0] -> 2.5.29.19 (Basic constraints, critical): 
                                CA: true
                                pathLenConstraint: 2 (0x2)
                        [1] -> 2.5.29.32 (Certificate policies) -> [0] -> 2.5.29.32.0 (Any Policy) -> [0] -> 1.3.6.1.5.5.7.2.1 (CPS) -> URI: http://cybertrust.omniroot.com/repository (type: IA5String)
                        [2] -> 2.5.29.15 (Key usage): 
                                5 (0x5): KeyCertSign
                                6 (0x6): CRLSign
                        [3] -> 2.5.29.35 (Authority key identifier) -> Identifier: e5:9d:59:30:82:47:58:cc:ac:fa:08:54:36:86:7b:3a:b5:04:4d:f0
                        [4] -> 2.5.29.31 (Revocation List distribution points) -> DistributionPoint[0] -> Name -> FullName -> [0] -> uniformResourceIdentifier: http://cdp1.public-trust.com/CRL/Omniroot2025.crl (type: IA5String)
                        [5] -> 2.5.29.14 (Subject key identifier) -> Value: b6:08:7b:0d:7a:cc:ac:20:4c:86:56:32:5e:cf:ab:6e:85:2d:70:57
                    Fingerprints: 
                        MD5: 1f:24:d9:81:41:b5:53:c5:95:09:f1:e6:ab:1e:16:e3 (synthetic)
                        SHA1: 45:12:de:a7:64:d6:70:73:46:3c:33:b6:04:68:64:4c:f7:af:a3:36 (synthetic)
                        SHA2-256: 9b:b5:cc:84:27:af:27:6b:f2:16:a7:48:ad:25:78:5d:17:ac:ba:bd:de:42:82:e6:06:da:52:62:cd:94:0f:38 (synthetic)
                        SHA3-256: 6e:b6:a0:0d:d6:9e:27:7b:f5:6a:f6:ea:9e:14:e7:cc:2e:02:fc:79:8e:ed:0c:f6:5e:e4:d8:55:ee:46:c9:ea (synthetic)
                    Security: 
                        CVE-2008-0166 (Openssl predictable random number generator): NotAffected (synthetic)
                        CVE-2017-15361 (ROCA: Vulnerable RSA generation): NotAffected (synthetic)
                2 (0x2): 
                    Version: v3
                    SerialNumber: 4835703278459898099219750 (hex: 0x4000000000141a1e13d26, bits: 88)
                    Signature: 
                        algo: 1.2.840.113549.1.1.11 (sha256WithRSAEncryption)
                        params: NULL
                    Issuer: 
                        [0] -> 2.5.4.10 (organizationName): Cybertrust, Inc (type: printableString)
                        [1] -> 2.5.4.3 (commonName): Cybertrust Global Root (type: printableString)
                    Subject: 
                        [0] -> 2.5.4.6 (countryName): BE (type: printableString)
                        [1] -> 2.5.4.3 (commonName): Belgium Root CA4 (type: printableString)
                    Validity: 
                        Duration: 11 years 7 months 2 days 59 minutes (synthetic)
                        NotBefore: 2013-10-10T11:00Z
                        NotAfter: 2025-05-12T22:59Z
                    SubjectPublicKeyInfo: 
                        Algorithm: 1.2.840.113549.1.1.1 (RSA)
                        modulus: 00:98:90:ae:fa:c7:1e:6f:8e:e0:05:3a:b3:23:78:4c:d1:d6:2f:dd:75:3c:5b:18:e8:4f:5e:bb:05:66:97:93:40:59:37:70:f6:9d:a6:72:61:0e:60:6c:78:db:88:c5:
                                 2e:94:90:54:dc:71:c6:88:77:2e:c2:29:75:65:0c:45:07:ee:88:3a:b3:bd:9c:7f:e1:d0:81:69:e2:8b:fc:03:11:26:e2:f5:77:ac:14:ef:75:ca:4a:47:43:af:9b:87:
                                 e8:7d:98:7f:5f:73:4a:25:0e:9b:6c:78:93:76:8d:2f:24:fe:56:bc:85:d7:56:f5:3e:ba:7a:ec:20:64:eb:73:81:98:6d:16:51:a0:7e:13:1b:41:1c:e9:1f:3d:a1:d1:
                                 1c:50:34:e0:c8:a0:a1:51:6d:de:02:d0:44:68:75:57:e1:f5:ae:6d:61:c9:d4:f3:77:ac:f3:a6:82:47:a7:7b:a3:58:3e:2b:e2:42:c2:af:15:45:57:44:19:e3:8b:ac:
                                 bc:03:e5:84:aa:1e:70:5d:1f:7a:22:ad:7a:04:b5:a5:2f:85:8c:61:c0:f5:2f:39:cb:16:64:9c:45:7c:37:a6:db:2b:96:0f:ee:48:0d:2c:30:c2:34:52:7a:1b:b3:0c:
                                 a5:ff:0c:13:28:17:58:c6:fe:5a:bc:a7:4d:eb:56:9c:85:7a:8d:3c:d9:03:54:66:69:9b:aa:98:83:03:bd:64:c0:ec:93:64:88:32:50:38:90:56:43:71:21:a7:e5:67:
                                 ee:58:b5:30:22:23:5e:51:03:60:9d:b0:46:67:11:65:0d:1b:b1:4c:da:33:f5:77:a7:e4:3e:8f:c4:b7:a2:c9:9a:dc:f7:3a:f9:d0:f3:c4:bf:8e:83:f9:67:46:72:e5:
                                 0d:aa:57:c7:6f:17:07:db:ab:51:1e:47:d3:73:b3:9b:be:c1:f7:f9:98:80:87:8c:f1:8d:57:9e:d9:42:08:42:c1:7a:e2:5e:11:82:54:a9:cd:05:b0:6c:56:37:08:ec:
                                 06:d4:68:67:87:6f:6b:5a:ef:ce:45:e6:8c:9b:8d:21:1e:18:20:b8:3c:1b:89:0a:2e:1a:fd:24:3a:ed:c8:29:2f:23:d5:e6:f0:60:e3:a9:02:09:d8:aa:50:88:91:c1:
                                 2c:90:34:80:ac:65:61:e9:bc:09:23:bf:6a:7d:c0:3b:1a:93:35:98:d6:6d:0c:7a:13:7d:8e:3c:1f:eb:b1:4d:bc:95:d6:9d:8b:d7:3c:c9:e4:72:5c:b5:a9:50:5e:06:
                                 86:3c:a8:73:83:9d:ac:09:17:9a:58:e7:93:32:cc:0b:8e:7d:c4:62:fc:82:3e:8b:c8:d6:fa:53:35:f4:79:80:3d
                        publicExponent: 01:00:01
                        Key length: 4096 (0x1000)
                        SHA1: 67:e8:f1:4e:4f:b3:b5:f3:07:6f:08:9c:0c:83:d9:7a:d9:5b:e7:49 (synthetic)
                        SHA2-256: 69:7f:9c:d0:b8:07:9b:57:5b:01:b8:ea:ee:58:cd:a1:8a:23:04:c3:09:2e:ef:90:fc:93:29:c8:c8:04:8d:27 (synthetic)
                        SHA3-256: 16:55:45:c7:98:88:91:ad:b1:3d:31:2a:4e:30:bf:33:2e:c7:c6:07:b8:2f:5b:14:d8:26:cd:90:a4:7a:2a:4a (synthetic)
                    Extensions: 
                        [0] -> 2.5.29.15 (Key usage, critical): 
                                5 (0x5): KeyCertSign
                                6 (0x6): CRLSign
                        [1] -> 2.5.29.19 (Basic constraints, critical): 
                                CA: true
                                pathLenConstraint: 1 (0x1)
                        [2] -> 2.5.29.32 (Certificate policies) -> [0] -> 1.3.6.1.4.1.6334.1.100.1 (Verizon Business/Cybertrust CPS v.5.2) -> [0] -> 1.3.6.1.5.5.7.2.1 (CPS) -> URI: http://cybertrust.omniroot.com/repository (type: IA5String)
                        [3] -> 2.5.29.14 (Subject key identifier) -> Value: 67:e8:f1:4e:4f:b3:b5:f3:07:6f:08:9c:0c:83:d9:7a:d9:5b:e7:49
                        [4] -> 2.5.29.31 (Revocation List distribution points) -> DistributionPoint[0] -> Name -> FullName -> [0] -> uniformResourceIdentifier: http://crl.omniroot.com/ctglobal.crl (type: IA5String)
                        [5] -> 2.16.840.1.113730.1.1 (Netscape Certificate Type): 
                                5 (0x5): SSLCA
                                6 (0x6): SMIMECA
                                7 (0x7): ObjectSigningCA
                        [6] -> 2.5.29.35 (Authority key identifier) -> Identifier: b6:08:7b:0d:7a:cc:ac:20:4c:86:56:32:5e:cf:ab:6e:85:2d:70:57
                    Fingerprints: 
                        MD5: 39:a3:87:96:04:60:e4:d9:7a:d6:96:01:4f:4a:c2:e3 (synthetic)
                        SHA1: 5f:e6:df:f5:d5:2c:ae:32:7a:37:c8:a1:c6:54:cd:b3:13:25:ba:09 (synthetic)
                        SHA2-256: 84:60:cc:ae:a9:1b:0e:80:5a:b5:1c:7c:d4:6d:df:2e:8c:1c:49:48:06:d8:8b:1f:e2:ed:31:3d:1d:48:7e:2e (synthetic)
                        SHA3-256: 36:5c:61:a6:2e:46:13:cb:3b:1d:40:ee:a4:07:f6:29:62:47:e2:8d:7d:f0:6e:47:36:1c:7c:3c:7e:07:43:70 (synthetic)
                    Security: 
                        CVE-2008-0166 (Openssl predictable random number generator): NotAffected (synthetic)
                        CVE-2017-15361 (ROCA: Vulnerable RSA generation): NotAffected (synthetic)
                3 (0x3): 
                    Version: v3
                    SerialNumber: 4835703278459997027741053 (hex: 0x4000000000158aa7aad7d, bits: 88)
                    Signature: 
                        algo: 1.2.840.113549.1.1.11 (sha256WithRSAEncryption)
                        params: NULL
                    Issuer: 
                        [0] -> 2.5.4.6 (countryName): BE (type: printableString)
                        [1] -> 2.5.4.3 (commonName): Belgium Root CA4 (type: printableString)
                    Subject: 
                        [0] -> 2.5.4.6 (countryName): BE (type: printableString)
                        [1] -> 2.5.4.5 (serialNumber): 2017 (type: printableString)
                        [2] -> 2.5.4.10 (organizationName): Belgium Federal Government (type: printableString)
                        [3] -> 2.5.4.3 (commonName): Time Stamping Authority (type: printableString)
                    Validity: 
                        Duration: 5 years 3 months (synthetic)
                        NotBefore: 2016-11-28T10:00Z
                        NotAfter: 2022-02-28T10:00Z
                    SubjectPublicKeyInfo: 
                        Algorithm: 1.2.840.113549.1.1.1 (RSA)
                        modulus: 00:a3:d3:b0:01:c8:bd:7e:dd:86:28:53:73:22:fd:21:bd:3a:52:2e:51:54:7b:1a:54:5e:f0:9b:05:90:af:0f:57:a4:34:43:26:80:35:de:5b:5e:a9:a8:23:c1:6c:99:
                                 30:ad:8b:a2:07:c5:b1:c9:62:be:f2:41:d4:f2:61:4f:f2:84:88:a3:9f:12:d0:b5:49:a7:34:77:5e:91:70:00:16:1d:c7:d3:c7:5d:80:a9:60:33:8f:de:7a:77:ad:bd:
                                 61:c1:bf:08:5a:9c:58:ef:2e:69:18:2c:f2:be:19:7d:07:54:c3:e3:13:fb:94:d9:b7:43:2e:4f:ba:19:f3:5a:91:46:e8:0e:92:24:a7:9c:36:40:e0:7b:f8:d5:d3:cd:
                                 fa:88:3e:e6:15:fc:e0:86:dd:91:87:80:fc:3f:72:56:fa:31:2e:3b:ab:f3:eb:8a:c8:b2:00:55:58:12:1f:b9:49:d4:bf:52:11:fe:f1:fd:2f:39:1d:25:59:e0:c9:ca:
                                 14:d9:ba:98:43:b2:09:20:2a:37:9a:09:2c:1f:8a:5f:57:97:a3:11:e5:c3:27:0f:bc:11:5b:b3:f6:79:ba:a3:41:89:d7:37:24:31:9d:81:17:30:89:7d:25:60:ab:3b:
                                 c4:37:b8:68:2f:ab:cc:be:1b:94:e8:75:84:1e:63:5a:67
                        publicExponent: 01:00:01
                        Key length: 2048 (0x800)
                        SHA1: 41:a6:41:fa:1f:54:dc:d6:42:cc:dd:f9:17:7d:62:95:3d:32:b0:9a (synthetic)
                        SHA2-256: 8f:71:43:77:d3:c9:58:5d:32:d7:b7:44:ae:41:0d:3f:cb:89:d4:8d:5d:f2:9e:ac:0a:6f:9c:4c:a2:1d:1e:88 (synthetic)
                        SHA3-256: 66:97:b0:94:65:b4:00:4b:c4:ea:c4:61:ac:d7:d7:a4:c5:72:19:55:a0:18:f9:bf:21:ba:5d:9d:15:c9:ba:f6 (synthetic)
                    Extensions: 
                        [0] -> 2.5.29.15 (Key usage, critical): 
                                0 (0x0): DigitalSignature
                                1 (0x1): ContentCommitment
                        [1] -> 2.5.29.37 (Extended key usage, critical) -> 1.3.6.1.5.5.7.3.8 (timeStamping)
                        [2] -> 2.5.29.32 (Certificate policies) -> [0] -> 2.16.56.12.1.1.5 (Belgium) -> [0] -> 1.3.6.1.5.5.7.2.1 (CPS) -> URI: http://repository.pki.belgium.be (type: IA5String)
                        [3] -> 2.5.29.14 (Subject key identifier) -> Value: 41:a6:41:fa:1f:54:dc:d6:42:cc:dd:f9:17:7d:62:95:3d:32:b0:9a
                        [4] -> 2.5.29.31 (Revocation List distribution points) -> DistributionPoint[0] -> Name -> FullName -> [0] -> uniformResourceIdentifier: http://crl.pki.belgium.be/belgium4.crl (type: IA5String)
                        [5] -> 2.5.29.19 (Basic constraints) -> None
                        [6] -> 2.5.29.35 (Authority key identifier) -> Identifier: 67:e8:f1:4e:4f:b3:b5:f3:07:6f:08:9c:0c:83:d9:7a:d9:5b:e7:49
                    Fingerprints: 
                        MD5: 81:f8:6d:94:1b:5c:49:fd:7c:af:69:d8:92:54:60:b0 (synthetic)
                        SHA1: 21:fa:16:57:cf:16:30:21:ae:79:29:89:46:31:3d:5e:41:86:45:ef (synthetic)
                        SHA2-256: ee:3c:22:e0:60:87:bf:ec:21:37:09:ad:3e:7f:2d:da:9c:e9:d1:9c:e2:38:dc:a8:1a:64:33:e9:07:0a:9f:be (synthetic)
                        SHA3-256: 11:0a:0e:2a:4b:c3:4d:38:d4:3f:60:06:ba:22:ae:39:6e:ea:c0:98:cd:79:d4:00:02:32:11:ca:1c:c9:ef:8b (synthetic)
                    Security: 
                        CVE-2008-0166 (Openssl predictable random number generator): NotAffected (synthetic)
                        CVE-2017-15361 (ROCA: Vulnerable RSA generation): NotAffected (synthetic)
            signerInfos -> [0]: 
                    version: 1 (0x1)
                    signerIdentifier: 
                        issuerName: 
                            [0] -> 2.5.4.6 (countryName): BE (type: printableString)
                            [1] -> 2.5.4.3 (commonName): Belgium Root CA4 (type: printableString)
                        serialNumber: 4835703278459997027741053 (0x4000000000158aa7aad7d)
                    digestAlgorithm: 1.3.14.3.2.26 (SHA1)
                    signedAttrs: 
                        [0] -> 1.2.840.113549.1.9.3 (Content Type): 1.2.840.113549.1.9.16.1.4 (id-ct-TSTInfo)
                        [1] -> 1.2.840.113549.1.9.4 (Message Digest) -> 1.2.840.113549.1.9.4 (Message Digest) -> [0]: 04:14:c2:9e:6d:fc:dc:a3:29:10:64:60:69:a8:6b:4b:da:ab:3a:39:4a:5b
                        [2] -> 1.2.840.113549.1.9.16.2.12 (SigningCertificate) -> ESSCertID: 
                                    certHash: 21:fa:16:57:cf:16:30:21:ae:79:29:89:46:31:3d:5e:41:86:45:ef
                                    issuerSerial -> [0] -> directoryName: 
                                                [0] -> 2.5.4.6 (countryName): BE (type: printableString)
                                                [1] -> 2.5.4.3 (commonName): Belgium Root CA4 (type: printableString)
                    signatureAlgorithm: 1.2.840.113549.1.1.1 (RSA)
                    signature: 55:1a:46:e8:b2:bd:2e:20:4a:7d:d6:a7:e5:a0:9f:07:26:65:4b:24:cd:f1:56:9b:36:bf:20:f3:84:83:ea:b4:29:2f:89:8c:87:1e:a6:d3:af:e3:6c:60:f7:31:35:3c:
                               f4:6b:ff:8e:4c:5b:cf:1a:f0:ff:00:d3:1f:c3:4a:da:1e:fb:66:b1:b3:f2:09:cd:d4:9c:0c:dc:f7:59:60:aa:4d:a6:9d:28:7a:4b:fc:59:7b:99:75:c8:a3:68:02:18:
                               c4:a1:b0:aa:03:d8:c2:59:36:23:0e:1e:9e:f0:37:7a:8e:83:6a:58:d4:bd:98:0c:48:94:8b:0d:ff:4b:17:9b:3c:b6:53:80:d6:c5:6a:ab:97:ac:e4:15:ab:a8:27:d4:
                               03:86:71:b6:f9:5f:f4:d4:99:19:fb:d0:90:ee:ad:af:e0:fd:d6:df:31:39:a9:ce:0c:6c:34:74:7c:55:0a:c9:fd:db:c3:f8:fd:12:66:a4:ce:a1:47:f1:1f:ca:53:f8:
                               b0:0e:9f:f6:b2:b9:64:7e:78:d0:a1:38:8d:88:15:5b:81:34:82:51:5f:01:f8:55:8b:00:b3:d7:3e:82:a8:28:6d:59:14:97:4e:3a:94:39:0e:85:40:12:b7:50:77:7b:
                               b6:21:ff:43:db:44:de:67:5e:90:0f:06:0e:c9:48:b7

```
