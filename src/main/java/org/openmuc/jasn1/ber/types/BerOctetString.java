/*
 * Copyright 2011-15 Fraunhofer ISE
 *
 * This file is part of jASN1.
 * For more information visit http://www.openmuc.org
 *
 * jASN1 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * jASN1 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with jASN1.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
package org.openmuc.jasn1.ber.types;

import org.openmuc.jasn1.ber.*;

import java.io.IOException;
import java.io.InputStream;

public class BerOctetString implements Asable, Encodedable, Decodeable {

    public final static BerIdentifier identifier = new BerIdentifier(BerIdentifier.UNIVERSAL_CLASS,
            BerIdentifier.PRIMITIVE, BerIdentifier.OCTET_STRING_TAG);
    protected BerIdentifier id;

    public byte[] value;
    public byte[] raw;

    public long from,to;

    public BerOctetString() {
        id = identifier;
    }

    public BerOctetString(byte[] value) {
        id = identifier;
        this.value = value;
    }

    public int encode(BerByteArrayOutputStream os, boolean explicit) throws IOException {

        os.write(value);
        int codeLength = value.length;

        codeLength += BerLength.encodeLength(os, codeLength);

        if (explicit) {
            codeLength += id.encode(os);
        }

        return codeLength;
    }


    public int decode(CountingInputStream is, boolean explicit) throws IOException {
from=is.getPosition();
        int codeLength = 0;
        if (!is.markSupported())
            throw new RuntimeException("NO MARK SUPPORT");
        is.mark(65535);
        try {
            if (explicit) {
                codeLength += id.decodeAndCheck(is);
            }

            BerLength length = new BerLength();
            codeLength += length.decode(is);

            value = new byte[length.val];

            if (length.val != 0) {
                Util.readFully(is, value);
                codeLength += length.val;
            }

            to=is.getPosition();
            return codeLength;
        } finally {
            is.reset();
            raw = new byte[codeLength];
            Util.readFully(is, raw);
        }

    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        if (value==null) {
            builder.append("null value");
        } else {
            for (byte element : value) {
                String hexString = Integer.toHexString(element & 0xff);
                if (hexString.length() == 1) {
                    builder.append("0");
                }
                builder.append(hexString);
            }
        }
        return builder.toString();
    }

    public byte[] getRaw() {
        return raw;
    }


    @Override
    public byte[] getValue() {
        return value;
    }

    @Override
    public long getFrom() {
        return from;
    }
}
