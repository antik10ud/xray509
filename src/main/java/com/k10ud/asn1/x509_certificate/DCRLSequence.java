
package com.k10ud.asn1.x509_certificate;

import org.openmuc.jasn1.ber.*;
import org.openmuc.jasn1.ber.types.string.BerIA5String;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;


public class DCRLSequence implements Encodedable, Decodeable, SourcePostitionable /*2*/ {

    public static final BerIdentifier identifier = new BerIdentifier(BerIdentifier.UNIVERSAL_CLASS, BerIdentifier.CONSTRUCTED, 16);
    protected BerIdentifier id;

    public byte[] code = null;
    public long from, to;
    public List<BerIA5String> seqOf = null;

    public DCRLSequence() {
        id = identifier;
        seqOf = new ArrayList<>();
    }

    public DCRLSequence(byte[] code) {
        id = identifier;
        this.code = code;
    }

    public DCRLSequence(List<BerIA5String> seqOf) {
        id = identifier;
        this.seqOf = seqOf;
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
            for (int i = (seqOf.size() - 1); i >= 0; i--) {
                codeLength += seqOf.get(i).encode(os, true);
            }

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

        while (subCodeLength < totalLength) {
            BerIA5String element = new BerIA5String();
            subCodeLength += element.decode(is, true);
            seqOf.add(element);
        }
        if (subCodeLength != totalLength) {
            throw new IOException("Decoded SequenceOf or SetOf has wrong length. Expected " + totalLength + " but has " + subCodeLength);

        }
        codeLength += subCodeLength;

        this.to = is.getPosition();
        return codeLength;
    }

    public void encodeAndSave(int encodingSizeGuess) throws IOException {
        BerByteArrayOutputStream os = new BerByteArrayOutputStream(encodingSizeGuess);
        encode(os, false);
        code = os.getArray();
    }

    public String toString() {
        StringBuilder sb = new StringBuilder("SEQUENCE OF{");

        if (seqOf == null) {
            sb.append("null");
        } else {
            Iterator<BerIA5String> it = seqOf.iterator();
            if (it.hasNext()) {
                sb.append(it.next());
                while (it.hasNext()) {
                    sb.append(", ").append(it.next());
                }
            }
        }

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

