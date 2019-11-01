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

package com.k10ud.certs.extensions;


import com.k10ud.certs.Item;
import org.openmuc.jasn1.ber.types.BerBitString;

public class Flags {

    public static class Bit {
        private final int bit;
        private final String name;

        public Bit(int bit, String name) {
            this.bit = bit;
            this.name = name;
        }

        public boolean in(byte[] value) {
            int idx = bit / 8;
            if (idx >= value.length)
                return false;
            return (value[idx] & 255 & 128 >> bit % 8) == 128 >> bit % 8;
        }

        public String getName() {
            return name;
        }

        public int getBit() {
            return bit;
        }
    }

    private final Bit[] bits;

    public Item in(BerBitString bitString) {
        if (bitString == null)
            return Item.EMPTY;
        Item flags = new Item();
        byte[] v = bitString.value;
        if (v != null)
            for (Bit i : bits)
                if (i.in(v))
                    flags.prop(i.bit, i.getName());

        return flags;
    }


    public Flags(Bit... bits) {
        this.bits = bits;
    }

}
