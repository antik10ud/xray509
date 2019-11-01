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

package org.openmuc.jasn1.ber;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

public interface Decodeable {

    default int decode(long sourceOffset,byte[] bytes, boolean explicit) throws IOException {
        return decode(new CountingInputStream(sourceOffset,new ByteArrayInputStream(bytes)), explicit);
    }


    default int decode(long sourceOffset,byte[] bytes) throws IOException {
        return decode(sourceOffset,bytes, true);
    }

    default int decode(CountingInputStream is) throws IOException {
        return decode(is, true);
    }

    default int decodeImplicit(long sourceOffset,byte[] bytes) throws IOException {
        return decode(new CountingInputStream(sourceOffset,new ByteArrayInputStream(bytes)), false);
    }


    default int decodeImplicit(CountingInputStream is) throws IOException {
        return decode(is, false);
    }
    int decode(CountingInputStream is, boolean explicit) throws IOException;

}