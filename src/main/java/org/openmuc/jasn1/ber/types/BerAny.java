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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

public class BerAny implements Encodedable {

    public byte[] value;
    public long from,to;

    public BerAny() {
    }

    public BerAny(byte[] value) {
        this.value = value;
    }

    public BerAny(BerIdentifier id) {
    }

    public int encode(BerByteArrayOutputStream os) throws IOException {
        os.write(value);
        return value.length;
    }

    public int decode(long offset, byte[] bytes, int len) throws IOException {
        return decode(new CountingInputStream(offset,new ByteArrayInputStream(bytes)), len);
    }

    public int decode(CountingInputStream is, int length) throws IOException {
        from=is.getPosition();
        value = new byte[length];

        if (length != 0) {
            Util.readFully(is, value);
        }
        to=is.getPosition();
        return length;
    }

    @Override
    public String toString() {
        return printHexBinary(value);
    }

    private static final char[] hexCode = "0123456789ABCDEF".toCharArray();

    public String printHexBinary(byte[] data) {
        StringBuilder r = new StringBuilder(data.length * 2);
        for (byte b : data) {
            r.append(hexCode[(b >> 4) & 0xF]);
            r.append(hexCode[(b & 0xF)]);
        }
        return r.toString();
    }

    public <T extends Decodeable> T  as(Class<T> dataClass,boolean b) {
        return Util.as(dataClass,from,value,b);
    }

    @Override
    public int encode(BerByteArrayOutputStream bor, boolean b) throws IOException {
        return encode(bor);
    }
}
