###### Usage
```
xray-crl 0.0.1
Usage: xray-crl [-h] [--all] [--dump-source-cert] [--show-encodings]
                [--show-sourcenames] [--text-format-compact-lines] [-c=<mode>]
                [-f=<format>] SOURCE
Dump RFC 6818 CRL Request
      SOURCE                  CRL file, certificate or URL to process.
      --all                   Process all available CRL in source certificate
      --dump-source-cert      Dump source certificate
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
View File CRL content
```
$ xray-crl src/test/java/docgen/acaapp2.crl
Source src/test/java/docgen/acaapp2.crl: 
    issuer: 
        [0] -> 2.5.4.6 (countryName): ES (type: printableString)
        [1] -> 2.5.4.7 (localityName): ZARAGOZA (type: printableString)
        [2] -> 2.5.4.10 (organizationName): ESPUBLICO SERVICIOS PARA LA ADMINISTRACION SA (type: printableString)
        [3] -> 2.5.4.11 (organizationalUnitName): AUTORIDAD DE CERTIFICACION ESFIRMA - AAPP (type: printableString)
        [4] -> 2.5.4.5 (serialNumber): A50878842 (type: printableString)
        [5] -> 2.5.4.3 (commonName): ESFIRMA AC AAPP 2 (type: printableString)
    tbsCertList: 
        version: 1 (v2)
        thisUpdate: 2018-06-13T09:43:54Z
        nextUpdate: 2018-06-14T09:43:54Z
        revokedCertificates: 
            [0]: 
                userCertificate: 1607009498202063527 (0x164d3e9fd30342a7)
                revocationDate: 2017-10-31T11:51:10Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [1]: 
                userCertificate: 2778586287989608907 (0x268f8581e16451cb)
                revocationDate: 2017-10-31T11:51:09Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [2]: 
                userCertificate: 1582383583777476779 (0x15f5c17c517750ab)
                revocationDate: 2017-10-10T10:01:37Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [3]: 
                userCertificate: 7256759325031886467 (0x64b530287d076e83)
                revocationDate: 2017-10-10T10:01:38Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [4]: 
                userCertificate: 6180976845456936816 (0x55c73db156600f70)
                revocationDate: 2017-10-31T11:51:09Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [5]: 
                userCertificate: 2638540221524029191 (0x249dfa5a15852f07)
                revocationDate: 2017-10-31T11:51:08Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [6]: 
                userCertificate: 985227830485938086 (0xdac3b7deaf16fa6)
                revocationDate: 2017-10-24T09:52:42Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 1 (keyCompromise)
            [7]: 
                userCertificate: 1916892077070569649 (0x1a9a2b301e8d50b1)
                revocationDate: 2017-10-31T11:51:09Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [8]: 
                userCertificate: 7392739662632324864 (0x6698498e04240f00)
                revocationDate: 2017-10-31T11:51:08Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [9]: 
                userCertificate: 7727562166642529933 (0x6b3dd0d92279d68d)
                revocationDate: 2017-10-31T11:51:09Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [10]: 
                userCertificate: 2290171839631573417 (0x1fc853277fd7c1a9)
                revocationDate: 2017-10-31T11:51:08Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [11]: 
                userCertificate: 5175074160901032179 (0x47d18e87d6cf08f3)
                revocationDate: 2017-10-31T11:51:08Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [12]: 
                userCertificate: 5702076484710895198 (0x4f21d85a194d0e5e)
                revocationDate: 2017-11-07T13:38:24Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 1 (keyCompromise)
            [13]: 
                userCertificate: 1309452155790846327 (0x122c1bcc44486977)
                revocationDate: 2018-06-11T10:03:27Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [14]: 
                userCertificate: 9017118299823915725 (0x7d233d51a6adc2cd)
                revocationDate: 2017-10-10T10:01:40Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [15]: 
                userCertificate: 3723760794483619492 (0x33ad74b697b8f6a4)
                revocationDate: 2017-10-31T11:51:09Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [16]: 
                userCertificate: 281239082756270453 (0x3e72974a8a4e975)
                revocationDate: 2017-10-31T11:51:10Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [17]: 
                userCertificate: 889611571428067906 (0xc588902c70c0a42)
                revocationDate: 2017-10-31T11:51:10Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [18]: 
                userCertificate: 6563384335349376518 (0x5b15d34758dce606)
                revocationDate: 2017-10-31T11:51:07Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [19]: 
                userCertificate: 7623409053152728020 (0x69cbca24aeaa53d4)
                revocationDate: 2017-10-31T11:51:08Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [20]: 
                userCertificate: 1841519839197154170 (0x198e6489762e4b7a)
                revocationDate: 2017-11-03T11:11:49Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 1 (keyCompromise)
            [21]: 
                userCertificate: 226821729720393716 (0x325d5295352dff4)
                revocationDate: 2017-10-31T11:51:10Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [22]: 
                userCertificate: 712520609289201747 (0x9e361b813d3e853)
                revocationDate: 2017-10-10T10:01:40Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [23]: 
                userCertificate: 175444371755099168 (0x26f4dba004de420)
                revocationDate: 2017-10-31T11:51:09Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [24]: 
                userCertificate: 2561851504118533597 (0x238d865ea6490ddd)
                revocationDate: 2018-06-04T11:31:14Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [25]: 
                userCertificate: 5704183358698314375 (0x4f29548aece85a87)
                revocationDate: 2017-10-31T11:51:09Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [26]: 
                userCertificate: 7984092467318374184 (0x6ecd31cc28623f28)
                revocationDate: 2017-10-31T11:51:10Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [27]: 
                userCertificate: 5602579200882581853 (0x4dc05c197699215d)
                revocationDate: 2017-10-31T11:51:08Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [28]: 
                userCertificate: 4701788202106093798 (0x41401b756ba800e6)
                revocationDate: 2017-10-31T11:51:08Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [29]: 
                userCertificate: 6217803920766548061 (0x564a13b8fc52385d)
                revocationDate: 2017-10-31T11:51:09Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [30]: 
                userCertificate: 8327377215419465049 (0x7390c97503c23d59)
                revocationDate: 2017-10-31T11:51:10Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [31]: 
                userCertificate: 2933345398067807877 (0x28b55619175bc685)
                revocationDate: 2017-10-10T10:01:40Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [32]: 
                userCertificate: 8781997881809607546 (0x79dfec8b637e9b7a)
                revocationDate: 2017-10-31T11:51:07Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [33]: 
                userCertificate: 1942277370909223749 (0x1af45afa6c52eb45)
                revocationDate: 2017-10-10T10:01:41Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [34]: 
                userCertificate: 7120718189203616975 (0x62d1df774524f4cf)
                revocationDate: 2017-10-31T11:51:07Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [35]: 
                userCertificate: 6146389938620562176 (0x554c5d158e837b00)
                revocationDate: 2017-10-31T11:51:10Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [36]: 
                userCertificate: 8154601706951151644 (0x712af70c2b9e101c)
                revocationDate: 2017-10-31T11:51:08Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [37]: 
                userCertificate: 1313146534829245725 (0x12393bd0ea88451d)
                revocationDate: 2017-10-31T11:51:08Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [38]: 
                userCertificate: 4482420498873347619 (0x3e34c1b1e1466e23)
                revocationDate: 2017-10-31T11:51:10Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [39]: 
                userCertificate: 295416440058215770 (0x41987afe27afd5a)
                revocationDate: 2017-10-31T11:51:09Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [40]: 
                userCertificate: 254650833009340599 (0x388b3955b4770b7)
                revocationDate: 2017-10-31T11:51:09Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [41]: 
                userCertificate: 3630496833994518082 (0x32621da2a46c6e42)
                revocationDate: 2017-10-31T11:51:10Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [42]: 
                userCertificate: 284596006814570954 (0x3f3168f72ad59ca)
                revocationDate: 2017-10-31T11:51:08Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [43]: 
                userCertificate: 7516706619092346392 (0x6850b4d847d3a618)
                revocationDate: 2018-06-04T11:29:29Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [44]: 
                userCertificate: 971945296589408998 (0xd7d0b190052cae6)
                revocationDate: 2017-10-10T10:01:40Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [45]: 
                userCertificate: 256217018902280669 (0x38e44056d1479dd)
                revocationDate: 2017-10-17T14:07:03Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 1 (keyCompromise)
            [46]: 
                userCertificate: 5736417199212575846 (0x4f9bd90cc281bc66)
                revocationDate: 2017-10-10T10:01:38Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [47]: 
                userCertificate: 1301881876738688349 (0x121136ab5287455d)
                revocationDate: 2017-11-07T13:34:33Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 1 (keyCompromise)
            [48]: 
                userCertificate: 5232415880859356217 (0x489d468567bc0c39)
                revocationDate: 2017-10-10T10:01:41Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [49]: 
                userCertificate: 1556369889324912105 (0x1599562b18534de9)
                revocationDate: 2017-10-10T10:01:41Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [50]: 
                userCertificate: 6099362267874746430 (0x54a549aab518603e)
                revocationDate: 2017-10-10T10:01:38Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [51]: 
                userCertificate: 1902353130312660936 (0x1a668417c9a377c8)
                revocationDate: 2017-10-31T11:51:09Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [52]: 
                userCertificate: 8635263238634394678 (0x77d69e29f8cad436)
                revocationDate: 2017-10-31T11:51:09Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [53]: 
                userCertificate: 422871540435737436 (0x5de576cf14b5b5c)
                revocationDate: 2017-10-31T11:51:10Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [54]: 
                userCertificate: 4474906652299397056 (0x3e1a0fe4255687c0)
                revocationDate: 2017-10-31T11:51:09Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [55]: 
                userCertificate: 7240650900752993289 (0x647bf5a1b1fe8c09)
                revocationDate: 2017-10-10T10:01:41Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
            [56]: 
                userCertificate: 4897950740659880826 (0x43f9043f8864c37a)
                revocationDate: 2017-10-31T11:51:09Z
                crlEntryExtensions -> [0] -> 2.5.29.21 (ReasonCode) -> Value: 5 (cessationOfOperation)
        signature: 
            algo: 1.2.840.113549.1.1.13 (sha512WithRSAEncryption(13))
            params: NULL
    crlExtensions: 
        [0] -> 2.5.29.35 (Authority key identifier) -> Identifier: f6:40:ef:c3:a7:2b:4d:e5:bf:31:e9:fa:ee:c3:79:79:1f:2a:03:58
        [1] -> 2.5.29.20 (CRL Number) -> Value: 483 (0x1e3)
    signatureAlgorithm: 
        algo: 1.2.840.113549.1.1.13 (sha512WithRSAEncryption(13))
        params: NULL
    signature: 81:4d:93:00:df:42:02:1e:7d:26:bf:2b:40:23:d2:d2:1e:30:50:bf:d8:c2:a6:bf:ec:3d:76:49:25:58:ca:ad:cd:77:1e:07:f7:3c:a5:7c:7c:26:7f:5a:0f:c9:9e:47:
               b2:4b:f5:0d:aa:03:48:5b:98:39:fa:50:29:32:68:00:e2:4f:1e:c6:20:fb:bd:a1:b3:0c:c8:40:31:60:a7:3f:d2:a6:cb:f3:2d:76:96:58:3a:31:47:df:2e:b3:d0:79:
               cf:42:e9:4d:38:7c:52:6d:6d:74:49:06:95:b9:58:b2:8b:fd:17:6b:81:2b:f8:38:ae:c4:1d:34:0f:86:84:66:9f:a0:af:05:ea:b3:b3:fb:71:a0:6b:78:df:1b:fd:9a:
               13:86:94:f5:29:7a:d0:67:23:f6:82:a5:d0:9e:5d:a7:7a:f9:58:b1:04:4d:b4:21:8e:b9:f9:9d:5a:de:88:6d:6d:92:d4:f1:ae:90:96:5e:6a:79:ab:de:2e:cf:e6:f8:
               a2:67:36:99:63:c2:75:14:e8:38:0f:c5:2d:3f:8b:74:f3:42:8c:58:4e:29:ca:61:1a:00:4b:7b:31:5b:07:d5:9d:f4:d1:58:21:e2:90:6d:ff:f6:73:e8:34:b4:fa:1a:
               85:ef:28:62:0f:8e:c4:ab:14:d2:e9:a0:73:d3:4d:36:1f:07:f1:f4:1b:43:4a:3a:45:32:da:01:06:fa:6d:63:12:aa:c2:9e:1b:e1:a6:c2:21:8c:ac:6a:ed:a6:7b:a0:
               af:29:ff:76:1a:28:cf:d2:8e:55:27:48:62:dd:6e:07:c2:64:56:af:a5:40:44:ce:43:34:93:94:12:d7:e8:73:fa:5d:53:ae:38:ff:3d:cc:6a:ce:31:69:13:48:6b:64:
               3e:0e:78:56:c1:df:e2:88:16:b2:f8:8b:db:c6:4e:06:2b:54:bc:04:a9:7e:1b:2d:33:82:cf:4d:68:09:5a:b1:94:40:88:91:3a:a1:a7:c4:8f:6b:53:26:4c:5b:b1:ca:
               6f:30:4c:26:0d:2d:3e:07:13:b5:ba:6b:af:e5:96:ae:9e:f3:7c:c5:42:c4:ed:9e:7d:3e:16:4d:ce:55:a6:09:b4:00:2e:fb:b2:da:ba:25:47:9f:e6:91:9f:58:e8:3d:
               60:eb:76:60:82:2b:74:a9:41:68:b1:f0:36:95:0a:16:a1:9d:ab:4c:b8:de:8d:bd:d5:74:15:00:56:11:35:8b:24:b6:3d:95:1e:4c:11:bc:12:1c:26:77:a5:0d:3c:e6:
               76:db:dc:95:ba:1b:c9:b0:18:1b:9f:72:e6:9c:91:92:76:0e:01:d8:47:d1:64:a9:98:d2:77:d3:ba:a2:1a:72

```
