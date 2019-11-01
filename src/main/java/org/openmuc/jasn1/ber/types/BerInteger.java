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


import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;

import org.openmuc.jasn1.ber.*;

import java.io.ByteArrayInputStream;

public class BerInteger implements SourcePostitionable {

    public final static BerIdentifier identifier = new BerIdentifier(BerIdentifier.UNIVERSAL_CLASS,
            BerIdentifier.PRIMITIVE, BerIdentifier.INTEGER_TAG);
    public BerIdentifier id;

    public byte[] code = null;
public long from,to;

    private byte[] value;

    public byte[] getRawValue() {
        return value;
    }

    public long getLong() {
        return new BigInteger(value).longValue();
    }

    public int getInt() {
        return new BigInteger(value).intValue();
    }

    public long getLongExact() {
        return new BigInteger(value).longValueExact();
    }

    public int getIntExact() {
        return new BigInteger(value).intValueExact();
    }

    public BigInteger getValue() {
        return new BigInteger(value);
    }

    public BigInteger getPositiveValue() {
        return new BigInteger(1, value);
    }

    public BerInteger() {
        id = identifier;
    }

    public BerInteger(byte[] code) {
        id = identifier;
        this.code = code;
    }

    public BerInteger(long val) {
        id = identifier;
        this.value = BigInteger.valueOf(val).toByteArray();
    }

    public BerInteger(BigInteger val) {
        id = identifier;
        this.value = val.toByteArray();
    }
    public int encode(BerByteArrayOutputStream os, boolean explicit) throws IOException {

        int codeLength;

        if (code != null) {
            codeLength = code.length;
            for (int i = code.length - 1; i >= 0; i--) {
                os.write(code[i]);
            }
        }
        else {

            //codeLength = 1;
            codeLength=value.length;

            /*while (value > (Math.pow(2, (8 * codeLength) - 1) - 1)
                    || value < Math.pow(-2, (8 * codeLength) - 1) && codeLength < 8) {
                codeLength++;
            }*/

            for (int i=value.length-1; i >=0; i--) {
                os.write(value[i]);
            }

            codeLength += BerLength.encodeLength(os, codeLength);
        }

        if (explicit) {
            codeLength += id.encode(os);
        }

        return codeLength;
    }

	public int decode(long offset,byte[] bytes, boolean explicit) throws IOException {
		return decode(new CountingInputStream(offset,new ByteArrayInputStream(bytes)), explicit);
	}


    public int decode(CountingInputStream is, boolean explicit) throws IOException {
from=is.getPosition();
        int codeLength = 0;

        if (explicit) {
            codeLength += id.decodeAndCheck(is);
        }

        BerLength length = new BerLength();
        codeLength += length.decode(is);
        byte[] byteCode = new byte[length.val];
        Util.readFully(is, byteCode);

    	value=byteCode;
        codeLength += length.val;
        to=is.getPosition();
        return codeLength;
    }

    public void encodeAndSave(int encodingSizeGuess) throws IOException {
        BerByteArrayOutputStream os = new BerByteArrayOutputStream(encodingSizeGuess);
        encode(os, false);
        code = os.getArray();
    }

    @Override
    public String toString() {
        return "" +  new BigInteger(value);
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
