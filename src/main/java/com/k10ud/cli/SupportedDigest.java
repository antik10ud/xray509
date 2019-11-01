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

import com.bakkenbaeck.token.crypto.cryptohash.Keccak256;
import com.k10ud.asn1.x509_certificate.AlgorithmIdentifier;
import org.openmuc.jasn1.ber.types.BerAny;
import org.openmuc.jasn1.ber.types.BerObjectIdentifier;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static com.k10ud.certs.util.ASN1Helper.intArray;


public enum SupportedDigest {
    SHA1("1.3.14.3.2.26", "SHA"),
    SHA2_256("2.16.840.1.101.3.4.2.1", "SHA-256"), //-- falta 224
    SHA2_384("2.16.840.1.101.3.4.2.2", "SHA-384"),
    SHA2_512("2.16.840.1.101.3.4.2.3", "SHA-512"),
    SHA3_256("2.16.840.1.101.3.4.2.8", "SHA3-256");
    private final String salg;
    private final int len;
    private String javaal;
    private final AlgorithmIdentifier algorithmIdentifier;

    SupportedDigest(String salg, String javaal) {
        this.salg = salg;
        this.javaal = javaal;
        int[] v = intArray(salg);
        algorithmIdentifier = new AlgorithmIdentifier(new BerObjectIdentifier(v), new BerAny(new byte[]{0x05, 0x00}));
        len = newMessageDigest(javaal).digest().length;
    }


    public String getJalg() {
        return javaal;
    }
    public String getSalg() {
        return salg;
    }

    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return algorithmIdentifier;
    }

    public static SupportedDigest forValue(AlgorithmIdentifier hashAlgorithm) {
        if (hashAlgorithm == null)
            throw new NullPointerException("hashAlgorithm");
        String searched = hashAlgorithm.algorithm.toString();
        for (SupportedDigest i : values()) {
            if (searched.equals(i.salg))
                return i;
        }
        throw new RuntimeException("Digest not found: " + searched);
    }

    public MessageDigest newMessageDigest() {
        return newMessageDigest(javaal);
    }
    private static  MessageDigest newMessageDigest(String javaal) {

        if ("SHA3-256".equals(javaal)) {
            return new MessageDigest(javaal) {
                Keccak256 keccak256 = new Keccak256();

                @Override
                protected void engineUpdate(byte input) {
                    keccak256.update(input);

                }

                @Override
                protected void engineUpdate(byte[] input, int offset, int len) {
                    keccak256.update(input, offset, len);

                }

                @Override
                protected byte[] engineDigest() {
                    return keccak256.digest();
                }

                @Override
                protected void engineReset() {
                    keccak256.reset();
                }
            };
        }
        try {
            return MessageDigest.getInstance(javaal);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

    }

    public int hashLen() {
        return len;
    }
}

