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

import org.openmuc.jasn1.ber.BerIdentifier;
import org.openmuc.jasn1.ber.BerLength;
import org.openmuc.jasn1.ber.CountingInputStream;
import org.openmuc.jasn1.ber.Decodeable;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

public class Util {

    public static void readFully(InputStream is, byte[] buffer) throws IOException {
        readFully(is, buffer, 0, buffer.length);
    }

    public static void readFully(InputStream is, byte[] buffer, int off, int len) throws IOException {

        do {

            int bytesRead = is.read(buffer, off, len);
            if (bytesRead == -1) {
                throw new EOFException("Unexpected end of input stream.");
            }

            len -= bytesRead;
            off += bytesRead;

        } while (len > 0);

    }

    public static <T extends Decodeable> T as(Class<T> classj, long offset, byte[] value) {
        return as(classj, offset,value, true);
    }

    public static <T extends Decodeable> T as(Class<T> classj, long offset, byte[] value, boolean b) {

        try {
            return decode(classj,  offset, value, b);
        } catch (IOException e) {
            return null;
        }

    }

    public static <T extends Decodeable> T decodeImplicit(Class<T> classj, long offset, byte[] value) throws IOException {
        return decode(classj, offset,value, false);
    }


    public static <T extends Decodeable> T decode(Class<T> classj, long offset, byte[] value) throws IOException {
        return decode(classj, offset,value, true);
    }

    public static <T extends Decodeable> T decode(Class<T> classj, long offset, byte[] value, boolean b) throws IOException {
        T t;
        try {
            t = classj.newInstance();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        t.decode(offset,value, b);
        return t;

    }


    public static <T extends Decodeable> T decodeAny(Class<T> x,long offset,  byte[] bytes) throws IOException {
        BerLength bl = new BerLength();
        CountingInputStream bais = new CountingInputStream(offset,new ByteArrayInputStream(bytes));

     //   BerIdentifier bi = new BerIdentifier();
       // bi.decode(bais);
        bl.decode(bais);
        byte[] mi = new byte[bl.val];
        readFully(bais, mi);
        return decode( x, offset,mi);

    }

}
