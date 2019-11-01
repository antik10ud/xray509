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

package com.k10ud.cli;

import com.k10ud.asn1.x509_certificate.AlgorithmIdentifier;
import org.openmuc.jasn1.ber.types.BerAny;
import org.openmuc.jasn1.ber.types.BerObjectIdentifier;

import java.security.NoSuchAlgorithmException;
import java.security.Signature;

import static com.k10ud.certs.util.ASN1Helper.intArray;


//!!fix
public enum SupportedSignatureAlg {
    SHA256withRSA("1.2.840.113549.1.1.1", "2.16.840.1.101.3.4.2.1", "SHA256withRSA"),
    SHAwithRSA("1.2.840.113549.1.1.1", "1.3.14.3.2.26", "SHA1withRSA"),;
    private final String salg;
    private String hash;
    private String javaal;
    private final AlgorithmIdentifier algorithmIdentifier;

    SupportedSignatureAlg(String salg, String hash, String javaal) {
        this.salg = salg;
        this.hash = hash;
        this.javaal = javaal;
        int[] v = intArray(salg);
        algorithmIdentifier = new AlgorithmIdentifier(new BerObjectIdentifier(v), new BerAny(new byte[]{0x05, 0x00}));

    }


    public String getSalg() {
        return salg;
    }

    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return algorithmIdentifier;
    }

    public static SupportedSignatureAlg forValue(AlgorithmIdentifier sigAlgorithm, AlgorithmIdentifier hashAlg) {
        if (sigAlgorithm == null || hashAlg == null)
            throw new NullPointerException("signatureAlgorithm");
        String searched = sigAlgorithm.algorithm.toString();
        String searched2 = hashAlg.algorithm.toString();
        for (SupportedSignatureAlg i : values()) {
            if (searched.equals(i.salg) && searched2.equals(i.hash))
                return i;
        }
        throw new RuntimeException("Signature alg not found: " + searched);
    }

    public static SupportedSignatureAlg forValue(String alg) {
        if (alg == null)
            throw new NullPointerException("alg");
        for (SupportedSignatureAlg i : values()) {
            if (alg.equals(i.salg) || alg.equals(i.javaal))
                return i;
        }
        throw new RuntimeException("Signature alg not found: " + alg);
    }

    public Signature getSignature() {
        try {
            return Signature.getInstance(javaal);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}

