/*
 * Copyright (c) 2019 David Castañón <antik10ud@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package com.k10ud.timestamps;

import com.k10ud.asn1.x509_certificate.*;
import com.k10ud.certs.util.ASN1Helper;
import com.k10ud.cli.SupportedDigest;

import java.io.IOException;
import java.util.Arrays;

public class SigningCertificateWrangler {
    private SigningCertificateV2 scv2;
    private String origin;
    private SigningCertificate sc;

    public SigningCertificateWrangler(String origin, SigningCertificateV2 scv2) {
        this.origin = origin;
        this.scv2 = scv2;
    }

    public SigningCertificateWrangler(String origin, SigningCertificate sc) {
        this.origin = origin;

        this.sc = sc;
    }

    public String getOrigin() {
        return origin;
    }

    public boolean isEquivalent(SigningCertificateWrangler scw2) {
        return true;
    }

    public boolean indetifies(Certificate certificate) {
        if (scv2 != null) {
            for (ESSCertIDv2 i : scv2.certs.seqOf) {
                if (i.certHash != null) {
                    try {
                        byte[] certHash = ASN1Helper.hash(i.hashAlgorithm == null ? "SHA-256" : i.hashAlgorithm.toString(), certificate.encoded());
                        if (Arrays.equals(certHash, i.certHash.value))
                            return true;
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }

        }
        if (sc != null) {
            byte[] certHash;
            try {

                certHash = ASN1Helper.hash(SupportedDigest.SHA1.getSalg(), certificate.encoded());
            } catch (IOException e) {
                return false;
            }
            for (ESSCertID i : sc.certs.seqOf) {
                if (i.certHash != null) {
                    if (Arrays.equals(certHash, i.certHash.value))
                        return true;

                }
            }

        }

        return false;
    }

}
