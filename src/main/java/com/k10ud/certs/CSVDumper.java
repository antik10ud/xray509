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

package com.k10ud.certs;


public class CSVDumper implements IItemDumper {


    public String toString(byte[] src, Item item) {
        StringBuilder sb = new StringBuilder();
        int columns = item.getProps().size();
        if (columns == 0)
            return "";
        /*for (KV i:item.getProps()) {
            writeValue(sb,i.getKey());
            writeComma(sb);
        }
        writeNewLine(sb);*/
        for (KV i : item.getProps()) {
            writeValue(sb, String.valueOf(i.getValue()));
            writeComma(sb);
        }
        sb.setLength(sb.length()-1);

        //writeNewLine(sb);
        return sb.toString();
    }

    private void writeNewLine(StringBuilder sb) {
        sb.append("\n");
    }

    private void writeComma(StringBuilder sb) {
        sb.append(",");
    }

    private void writeValue(StringBuilder sb, String value) {
        if (value.contains(",")) {
            value = value.replaceAll("\"", "\"\"");
            sb.append("\"");
            sb.append(value);
            sb.append("\"");

        } else {
            sb.append(value);
        }

    }


}
