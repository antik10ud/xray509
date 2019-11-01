###### Usage
```
$ xray-cert --help
xray-cert 0.0.1
Usage: xray-cert [-h] [--show-encodings] [--show-sourcenames]
                 [--text-format-compact-lines] [--query=<text>] [-c=<mode>]
                 [-f=<format>] SOURCE [SOURCE...]
Dump x509 certificates
      SOURCE                  X509Certificate sources such as pem or der files,
                                URLs, tls:<host>, data:<base64data>
      --query=<text>          Query certificates
                                Default: null
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
View Certificate Content
```
$ xray-cert src/test/java/docgen/google.pem
Version: v3
SerialNumber: 315689065623421815864785010228154928589 (hex: 0xed7f80a1379302560800000000190dcd, bits: 136)
Signature: 
    algo: 1.2.840.113549.1.1.11 (sha256WithRSAEncryption)
    params: NULL
Issuer: 
    [0] -> 2.5.4.6 (countryName): US (type: printableString)
    [1] -> 2.5.4.10 (organizationName): Google Trust Services (type: printableString)
    [2] -> 2.5.4.3 (commonName): GTS CA 1O1 (type: printableString)
Subject: 
    [0] -> 2.5.4.6 (countryName): US (type: printableString)
    [1] -> 2.5.4.8 (stateOrProvinceName): California (type: printableString)
    [2] -> 2.5.4.7 (localityName): Mountain View (type: printableString)
    [3] -> 2.5.4.10 (organizationName): Google LLC (type: printableString)
    [4] -> 2.5.4.3 (commonName): www.google.com (type: printableString)
Validity: 
    Duration: 2 months 23 days (synthetic)
    NotBefore: 2019-10-10T20:56:23Z
    NotAfter: 2020-01-02T20:56:23Z
SubjectPublicKeyInfo: 
    Algorithm: 1.2.840.10045.2.1 (ecPublicKey)
    Named curve: 1.2.840.10045.3.1.7 (NIST-P256/secp256r1)
    EC point: 0b:dc:3b:c1
    SHA1: 19:79:86:24:4a:e6:9a:46:af:ac:ec:e4:8e:43:8d:1a:60:6e:bc:f4 (synthetic)
    SHA2-256: be:f3:23:cc:ce:cf:73:ee:5f:91:2f:d8:1e:d1:88:4c:95:d7:67:37:f9:aa:39:0c:17:1f:e4:d7:49:39:31:2c (synthetic)
    SHA3-256: 58:49:d9:da:e1:ad:d5:e5:17:ab:f7:29:07:3f:b3:76:ba:97:c6:94:f0:56:c3:dd:0d:c4:34:84:56:82:90:41 (synthetic)
Extensions: 
    [0] -> 2.5.29.15 (Key usage, critical) -> 0 (0x0): DigitalSignature
    [1] -> 2.5.29.37 (Extended key usage) -> 1.3.6.1.5.5.7.3.1 (serverAuth)
    [2] -> 2.5.29.19 (Basic constraints, critical) -> None
    [3] -> 2.5.29.14 (Subject key identifier) -> Value: 19:79:86:24:4a:e6:9a:46:af:ac:ec:e4:8e:43:8d:1a:60:6e:bc:f4
    [4] -> 2.5.29.35 (Authority key identifier) -> Identifier: 98:d1:f8:6e:10:eb:cf:9b:ec:60:9f:18:90:1b:a0:eb:7d:09:fd:2b
    [5] -> 1.3.6.1.5.5.7.1.1 (Authority Information Access): 
            AccessDescription[0]: 
                Method: 1.3.6.1.5.5.7.48.1 (ocsp)
                Location -> uniformResourceIdentifier: http://ocsp.pki.goog/gts1o1 (type: IA5String)
            AccessDescription[1]: 
                Method: 1.3.6.1.5.5.7.48.2 (caIssuers)
                Location -> uniformResourceIdentifier: http://pki.goog/gsr2/GTS1O1.crt (type: IA5String)
    [6] -> 2.5.29.17 (Subject alternative name): 
            [0] -> DNSName: www.google.com (type: IA5String)
    [7] -> 2.5.29.32 (Certificate policies): 
            [0] -> 2.23.140.1.2.2 (organization-validated CA/Browser Forum's Baseline Requirements)
            [1] -> 1.3.6.1.4.1.11129.2.5.3 (United States Department of Defense (DoD))
    [8] -> 2.5.29.31 (Revocation List distribution points) -> DistributionPoint[0] -> Name -> FullName -> [0] -> uniformResourceIdentifier: http://crl.pki.goog/GTS1O1.crl (type: IA5String)
    [9] -> 1.3.6.1.4.1.11129.2.4.2 (Certificate Transparency Precertificate SCTs): 
            [0]: 
                sct_version: 0 (v1)
                id: b2:1e:05:cc:8b:a2:cd:8a:20:4e:87:66:f9:2b:b9:8a:25:20:67:6b:da:fa:70:e7:b2:49:53:2d:ef:8b:90:5e
                timestamp: 2019-10-10T21:56:23.869Z
                extensions -> none
                digitally-signed: 
                    algorithms: 
                        hash: 4 (sha256)
                        signature: 3 (ecdsa)
                    signature: 00:47:30:45:02:20:67:77:56:d7:0a:c6:3e:0c:8d:cd:7e:3d:38:22:e7:46:f9:e5:c9:12:12:9b:23:97:e3:b9:19:3f:68:51:2d:12:02:21:00:a1:96:ce:5d:2d:5f:42:c2:5e:c6:1f:5b:3f:73:d2:f1:5c:c5:74:04:f9:a0:3d:9b:0e:77:6f:88:ce:63:8f:aa
            [1]: 
                sct_version: 0 (v1)
                id: 5e:a7:73:f9:df:56:c0:e7:b5:36:48:7d:d0:49:e0:32:7a:91:9a:0c:84:a1:12:12:84:18:75:96:81:71:45:58
                timestamp: 2019-10-10T21:56:23.896Z
                extensions -> none
                digitally-signed: 
                    algorithms: 
                        hash: 4 (sha256)
                        signature: 3 (ecdsa)
                    signature: 00:46:30:44:02:20:70:28:b7:34:89:88:26:06:22:97:e6:d0:f1:85:61:c1:17:06:66:ab:d6:8f:9d:06:47:9a:f0:87:77:c5:8d:02:02:20:3b:e0:b6:6b:ac:9c:85:14:74:cd:ba:28:9e:85:e9:51:6c:a0:f8:b0:b2:10:8d:6b:e3:de:ee:c8:3a:49:04:dd
Fingerprints: 
    MD5: 27:65:a9:b2:d2:af:4a:9d:a3:69:b4:6c:3c:32:fc:a3 (synthetic)
    SHA1: 54:97:ae:80:f5:16:a6:91:48:b0:91:d3:9e:01:a4:27:83:5f:b0:fc (synthetic)
    SHA2-256: 00:4a:69:39:2b:93:d1:a8:95:1e:be:c1:4f:2f:a8:64:41:07:89:3d:2e:25:fe:5d:b4:d1:26:08:34:2e:dc:70 (synthetic)
    SHA3-256: 58:41:98:4d:cd:e0:9f:5c:ef:40:d2:f4:d1:ee:50:f7:3b:a1:9e:9f:37:bd:d4:e2:8d:ca:c1:40:5c:0c:6d:04 (synthetic)
Security: 
    CVE-2008-0166 (Openssl predictable random number generator): Unknown (synthetic)
    CVE-2017-15361 (ROCA: Vulnerable RSA generation): NotAffected (synthetic)

```
###### Sample 2
View EIDAS Certificate Content
```
$ xray-cert src/test/java/docgen/eidas.pem
unsupported
```
###### Sample 3
Query certificate elements using the x509 Query Language. You can also use multiple certs to do a certificate filtered search
```
$ xray-cert --query MATCH Extensions/**/$qcType:=0.4.0.1862.1.6 RETURN $qcType src/test/java/docgen/eidas.pem
qcType -> 0.4.0.1862.1.6.1 (esign)

```
