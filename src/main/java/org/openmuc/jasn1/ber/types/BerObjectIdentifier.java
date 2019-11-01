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

import com.k10ud.certs.util.ASN1Helper;
import org.openmuc.jasn1.ber.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public class BerObjectIdentifier implements Encodedable,Decodeable {

    public final static BerIdentifier identifier = new BerIdentifier(BerIdentifier.UNIVERSAL_CLASS,
            BerIdentifier.PRIMITIVE, BerIdentifier.OBJECT_IDENTIFIER_TAG);
    protected BerIdentifier id;

    public byte[] code = null;
public long from, to;
    public int[] value;

    public BerObjectIdentifier() {
        id = identifier;
    }

    public BerObjectIdentifier(byte[] code) {
        id = identifier;
        this.code = code;
    }

    public BerObjectIdentifier(int[] value) {
        id = identifier;
        if ((value.length < 2) || ((value[0] == 0 || value[0] == 1) && (value[1] > 39)) || value[0] > 2) {
            throw new IllegalArgumentException("invalid object identifier components");
        }
        for (int objectIdentifierComponent : value) {
            if (objectIdentifierComponent < 0) {
                throw new IllegalArgumentException("invalid object identifier components");
            }
        }

        this.value = value;

    }

    public int encode(BerByteArrayOutputStream os, boolean explicit) throws IOException {

        int codeLength;

        if (code != null) {
            codeLength = code.length;
            for (int i = code.length - 1; i >= 0; i--) {
                os.write(code[i]);
            }
        } else {
            int firstSubidentifier = 40 * value[0] + value[1];

            int subidentifier;

            codeLength = 0;

            for (int i = (value.length - 1); i > 0; i--) {


                if (i == 1) {
                    subidentifier = firstSubidentifier;
                } else {
                    subidentifier = value[i];
                }

                // get length of subidentifier
                int subIDLength = 1;
                while (subidentifier > (Math.pow(2, (7 * subIDLength)) - 1)) {
                    subIDLength++;
                }

                os.write(subidentifier & 0x7f);

                for (int j = 1; j <= (subIDLength - 1); j++) {
                    os.write(((subidentifier >> (7 * j)) & 0xff) | 0x80);
                }

                codeLength += subIDLength;
            }
            //ASN1Helper.bytesToHex(os.getArray(),"");
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

        if (length.val == 0) {
            value = new int[0];
            return codeLength;
        }

        byte[] byteCode = new byte[length.val];
        Util.readFully(is, byteCode);

        codeLength += length.val;

        List<Integer> objectIdentifierComponentsList = new ArrayList<>();

        int subIDEndIndex = 0;
        while ((byteCode[subIDEndIndex] & 0x80) == 0x80) {
            if (subIDEndIndex >= (length.val - 1)) {
                throw new IOException("Invalid Object Identifier");
            }
            subIDEndIndex++;
        }

        int subidentifier = 0;
        for (int i = 0; i <= subIDEndIndex; i++) {
            subidentifier |= (byteCode[i] << ((subIDEndIndex - i) * 7));
        }

        if (subidentifier < 40) {
            objectIdentifierComponentsList.add(0);
            objectIdentifierComponentsList.add(subidentifier);
        } else if (subidentifier < 80) {
            objectIdentifierComponentsList.add(1);
            objectIdentifierComponentsList.add(subidentifier - 40);
        } else {
            objectIdentifierComponentsList.add(2);
            objectIdentifierComponentsList.add(subidentifier - 80);
        }

        subIDEndIndex++;

        while (subIDEndIndex < length.val) {
            int subIDStartIndex = subIDEndIndex;

            while ((byteCode[subIDEndIndex] & 0x80) == 0x80) {
                if (subIDEndIndex == (length.val - 1)) {
                    throw new IOException("Invalid Object Identifier");
                }
                subIDEndIndex++;
            }
            subidentifier = 0;
            for (int j = subIDStartIndex; j <= subIDEndIndex; j++) {
                subidentifier |= ((byteCode[j] & 0x7f) << ((subIDEndIndex - j) * 7));
            }
            objectIdentifierComponentsList.add(subidentifier);
            subIDEndIndex++;
        }

        value = new int[objectIdentifierComponentsList.size()];
        for (int i = 0; i < objectIdentifierComponentsList.size(); i++) {
            value[i] = objectIdentifierComponentsList.get(i);
        }

        to=is.getPosition();

        return codeLength;

    }

    @Override
    public String toString() {
        if (value == null || value.length == 0) {
            return "";
        }

        String objIDString = "";
        objIDString += value[0];
        for (int i = 1; i < value.length; i++) {
            objIDString += "." + value[i];
        }
        return objIDString;
    }

}
