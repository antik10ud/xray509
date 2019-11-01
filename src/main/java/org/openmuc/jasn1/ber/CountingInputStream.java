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

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;


public final class CountingInputStream extends FilterInputStream {
    private final long offset;
    private long count;
    private long mark = -1L;

    public CountingInputStream(long offset,InputStream in) {
        super(in);
        this.offset = offset;
    }

    public CountingInputStream(InputStream in) {
        this(0,in);
    }

    public long getPosition() {
        return this.count + offset;
    }

    public int read() throws IOException {
        int result = this.in.read();
        if (result != -1) {
            ++this.count;
        }

        return result;
    }

    public int read(byte[] b, int off, int len) throws IOException {
        int result = this.in.read(b, off, len);
        if (result != -1) {
            this.count += (long) result;
        }

        return result;
    }

    public long skip(long n) throws IOException {
        long result = this.in.skip(n);
        this.count += result;
        return result;
    }

    public synchronized void mark(int readlimit) {
        this.in.mark(readlimit);
        this.mark = this.count;
    }

    public synchronized void reset() throws IOException {
        if (!this.in.markSupported()) {
            throw new IOException("Mark not supported");
        } else if (this.mark == -1L) {
            throw new IOException("Mark not set");
        } else {
            this.in.reset();
            this.count = this.mark;
        }
    }
}
