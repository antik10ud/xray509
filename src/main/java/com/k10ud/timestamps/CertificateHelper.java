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

import com.k10ud.asn1.x509_certificate.Certificate;
import com.k10ud.asn1.x509_certificate.GeneralName;
import com.k10ud.asn1.x509_certificate.RSAPublicKey;
import com.k10ud.certs.util.ASN1Helper;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

public class CertificateHelper {
    public static boolean hasAnySubjectName(GeneralName subject, Certificate c) {

        return ASN1Helper.generalName(subject).equals(ASN1Helper.name(c.tbsCertificate.subject));

    }

    public static PublicKey publicKey(Certificate signerCertificate) {

        RSAPublicKey rsapk = new RSAPublicKey();
        try {
            rsapk.decode(signerCertificate.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey.from,signerCertificate.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey.value, true);
        } catch (IOException e) {
          return null;
        }

        try {
            return KeyFactory.getInstance("RSA").generatePublic(
                    new RSAPublicKeySpec(
                            rsapk.modulus.getPositiveValue(),
                            rsapk.publicExponent.getPositiveValue()));
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }
}
