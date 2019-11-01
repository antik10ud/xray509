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

package com.k10ud.certs.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;

public class RelaxedPemReader extends BufferedReader {
    private static final String BEGIN = "-----BEGIN ";
    private static final String END = "-----END ";

    public RelaxedPemReader(Reader in) {
        super(in);
    }

    public byte[] read(String type) throws IOException {
        String line;
        String beginMarker = (BEGIN + type + "-----").toUpperCase();
        String endMarker = (END + type + "-----").toUpperCase();
        StringBuffer buf = new StringBuffer();
        //List            headers = new ArrayList();

        while ((line = readLine()) != null) {
            String lineUp=line.toUpperCase();
            if (line.indexOf(":") >= 0) {
                int index = line.indexOf(':');
                String hdr = line.substring(0, index);
                String value = line.substring(index + 1).trim();

                //headers.add(new PemHeader(hdr, value));

                continue;
            }

            if (lineUp.indexOf(endMarker) != -1) {
                buf.append(line.substring(0, line.indexOf(endMarker)));
                break;
            }

            if (lineUp.indexOf(beginMarker) != -1) {
                buf.setLength(0);
                line = line.substring(line.indexOf(beginMarker) + beginMarker.length());
            }

            buf.append(line.trim());
        }

        return Base64.decode(buf.toString());
    }

}
