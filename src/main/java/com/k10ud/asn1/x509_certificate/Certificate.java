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

/**
 * This class file was automatically generated by jASN1 v1.6.0 (http://www.openmuc.org)
 */

package com.k10ud.asn1.x509_certificate;

import org.openmuc.jasn1.ber.*;
import org.openmuc.jasn1.ber.types.BerBitString;

import java.io.ByteArrayInputStream;
import java.io.IOException;


public class Certificate implements Encodedable, Decodeable, SourcePostitionable /*3*/ {

    public static final BerIdentifier identifier = new BerIdentifier(BerIdentifier.UNIVERSAL_CLASS, BerIdentifier.CONSTRUCTED, 16);
    protected BerIdentifier id;

    public byte[] code = null;
    public long from, to;
    public TBSCertificate tbsCertificate = null;

    public AlgorithmIdentifier signatureAlgorithm = null;

    public BerBitString signatureValue = null;

    public Certificate() {
        id = identifier;
    }

    public Certificate(byte[] code) {
        id = identifier;
        this.code = code;
    }

    public Certificate(TBSCertificate tbsCertificate, AlgorithmIdentifier signatureAlgorithm, BerBitString signatureValue) {
        id = identifier;
        this.tbsCertificate = tbsCertificate;
        this.signatureAlgorithm = signatureAlgorithm;
        this.signatureValue = signatureValue;
    }

    public int encode(BerByteArrayOutputStream os, boolean explicit) throws IOException {

        int codeLength;

        if (code != null) {
            codeLength = code.length;
            for (int i = code.length - 1; i >= 0; i--) {
                os.write(code[i]);
            }
        } else {
            codeLength = 0;
            codeLength += signatureValue.encode(os, true);

            codeLength += signatureAlgorithm.encode(os, true);

            codeLength += tbsCertificate.encode(os, true);

            codeLength += BerLength.encodeLength(os, codeLength);
        }

        if (explicit) {
            codeLength += id.encode(os);
        }

        return codeLength;
    }

    public int decode(long sourceOffset, byte[] bytes, boolean explicit) throws IOException {
        return decode(new CountingInputStream(sourceOffset, new ByteArrayInputStream(bytes)), explicit);

    }

    public int decode(CountingInputStream is, boolean explicit) throws IOException {
        int codeLength = 0;
        this.from = is.getPosition();
        int subCodeLength = 0;
        BerIdentifier berIdentifier = new BerIdentifier();

        if (explicit) {
            codeLength += id.decodeAndCheck(is);
        }

        BerLength length = new BerLength();
        codeLength += length.decode(is);

        int totalLength = length.val;
        codeLength += totalLength;

        subCodeLength += berIdentifier.decode(is);
        if (berIdentifier.equals(TBSCertificate.identifier)) {
            tbsCertificate = new TBSCertificate();
            subCodeLength += tbsCertificate.decode(is, false);
            subCodeLength += berIdentifier.decode(is);
        } else {
            throw new IOException("Identifier does not match the mandatory sequence element identifer.");
        }

        if (berIdentifier.equals(AlgorithmIdentifier.identifier)) {
            signatureAlgorithm = new AlgorithmIdentifier();
            subCodeLength += signatureAlgorithm.decode(is, false);
            subCodeLength += berIdentifier.decode(is);
        } else {
            throw new IOException("Identifier does not match the mandatory sequence element identifer.");
        }

        if (berIdentifier.equals(BerBitString.identifier)) {
            signatureValue = new BerBitString();
            subCodeLength += signatureValue.decode(is, false);
            if (subCodeLength == totalLength) {
                this.to = is.getPosition();
                return codeLength;
            }
        }
        throw new IOException("Unexpected end of sequence, length tag: " + totalLength + ", actual sequence length: " + subCodeLength);


    }

    public void encodeAndSave(int encodingSizeGuess) throws IOException {
        BerByteArrayOutputStream os = new BerByteArrayOutputStream(encodingSizeGuess);
        encode(os, false);
        code = os.getArray();
    }

    public String toString() {
        StringBuilder sb = new StringBuilder("SEQUENCE{");
        sb.append("tbsCertificate: ").append(tbsCertificate);

        sb.append(", ");
        sb.append("signatureAlgorithm: ").append(signatureAlgorithm);

        sb.append(", ");
        sb.append("signatureValue: ").append(signatureValue);

        sb.append("}");
        return sb.toString();
    }

    @Override

    public long getFrom() {

        return from;

    }

    @Override

    public long getTo() {

        return to;

    }

}

