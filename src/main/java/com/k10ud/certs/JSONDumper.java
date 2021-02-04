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


import com.k10ud.certs.util.Base64;
import org.openmuc.jasn1.ber.SourcePostitionable;

public class JSONDumper implements IItemDumper {


    public JSONDumper() {

    }

    public String toString(byte[] src,Item item) {
        StringBuilder sb = new StringBuilder();
        StringBuilder prefix = new StringBuilder();
        toString(prefix, sb, item);
        return sb.toString();
    }

    public void toString(StringBuilder prefix, StringBuilder sb, Item item) {
        sb.append("\n");
        sb.append(prefix);
        sb.append("{\n");
        right(prefix);
        boolean comma = false;
        for (KV i : item.getProps()) {
            sb.append(prefix);
            if (comma)
                sb.append(",\n");
            dump(sb, i.key);

            sb.append(": ");
            if (i.value != null) {
                if (i.value instanceof SourcePostitionable) {
                    SourcePostitionable sp = ((SourcePostitionable) i.value);
                    long from=sp.getFrom();
                    long to= sp.getTo();
                    sb.append(String.format("{\"from\":\"%d\",\"to\":\"%d\"}\n", from,to));
                }
                else if (i.value instanceof Item) {

                    right(prefix);
                    toString(prefix, sb, (Item) i.value);
                    left(prefix);

                } else {

                    dump(sb, i.value);

                }
            } else {
                sb.append("\"\"");
            }
            comma = true;
        }
        left(prefix);
        sb.append(prefix);
        sb.append("}\n");
    }

    private void dump(StringBuilder sb, Object i) {
        if (i == null)
            return;
        try {
            if (i instanceof Number) {
                sb.append(quoted(String.valueOf(i)));
            } else if (i instanceof byte[]) {
                sb.append(quoted(Base64.encodeBytes((byte[]) i, Base64.DONT_BREAK_LINES)));
            } else if (i instanceof TaggedString) {
                TaggedString ts = (TaggedString) i;
                sb.append("{");
                sb.append("\"value\":");
                dump(sb,ts.getId());
                sb.append(",\"tags\":");

                if (ts.tagCount() > 0) {
                    sb.append("{");
                    boolean comma = false;
                    for (TaggedString.Attr j : ts.tags()) {
                        if (comma) {
                            sb.append(", ");
                        }
                        String v = j.getValue();
                        String t = j.getAttr();

                        sb.append(quoted(t));
                        sb.append(": ");
                        if (v == null)
                            sb.append(quoted("true"));
                        else
                            sb.append(quoted(v));
                        comma = true;

                    }

                    sb.append("}\n");
                } else {
                    sb.append("{}\n");
                }

                sb.append("}\n");
            } else {
                sb.append(quoted(i.toString()));
            }
        } catch (Exception x) {
            x.printStackTrace();
            sb.append("{\"unprocessable\":\"" + i + "\"}\n");
        }
    }

    private String quoted(String s) {
        return "\"" + s + "\"";
    }

    private void right(StringBuilder prefix) {
        prefix.append(" ");
    }

    private void left(StringBuilder prefix) {
        prefix.setLength(prefix.length() - 1);
    }


}

