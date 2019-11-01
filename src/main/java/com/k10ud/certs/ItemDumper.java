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


import com.k10ud.certs.util.ASN1Helper;
import com.k10ud.certs.util.ItemHelper;
import com.k10ud.certs.util.XPrint;

import java.util.List;

import static picocli.CommandLine.Help.*;

public class ItemDumper implements IItemDumper {


    private final Ansi ansi;
    private boolean compactLines;
    private boolean showEncodings;


    public ItemDumper(Ansi ansi, boolean compactLines, boolean showEncodings) {
        this.ansi = ansi;
        this.compactLines = compactLines;
        this.showEncodings = showEncodings;
    }

    public ItemDumper() {
        this(Ansi.AUTO, true, false);
    }

    public String toString(byte[] src,Item item) {
        StringBuilder sb = new StringBuilder();
        StringBuilder prefix = new StringBuilder();
        toString(prefix, sb, item);
        ColorScheme colorScheme = defaultColorScheme(ansi);
        return colorScheme.ansi().new Text(sb.toString()).toString();
    }

    public void toString(StringBuilder prefix, StringBuilder sb, Item item) {
        List<KV> props = item.getProps();

        int n = props.size();
        if (n > 1 || !compactLines) {
            if (sb.length() > 0)
                sb.append("\n");
        } else if (n == 1)
            if (sb.length() > 0)
                sb.append(" -> ");

        for (KV i : props) {
            if (i.key.toString().startsWith("@") && !showEncodings)
                continue;
            if (n > 1 || !compactLines)
                sb.append(prefix);
            dump(sb, i.key);
            if (i.value != null) {
                if (i.value instanceof Item) {
                    int s = ((Item) i.value).size();
                    if (s > 0) {
                        if (s > 1)
                            sb.append(": ");
                        right(prefix);
                        toString(prefix, sb, (Item) i.value);
                        left(prefix);
                    }
                } else {
                    sb.append(": ");

                    dump(sb, i.value, true);

                }
            }
            if (sb.length() > 0 && sb.charAt(sb.length() - 1) != '\n')
                sb.append("\n");
        }
        if ((n > 1 || !compactLines) && sb.length() > 0 && sb.charAt(sb.length() - 1) != '\n')
            sb.append("\n");
    }

    private void dump(StringBuilder sb, Object i) {
        dump(sb, i, false);
    }

    private void dump(StringBuilder sb, Object i, boolean bold) {
        if (i == null)
            return;
        try {
           /* if (i instanceof BigInteger) {
                BigInteger n = (BigInteger) i;

                sb.append(String.format("%s (0x%x, %dbits)", bolds(bold, String.valueOf(i)), i, n.bitLength()));
            } else*/

           if (i instanceof XPrint) {
               sb.append(ItemHelper.cmds_xprint(((XPrint)i).getBytes(),detectPrefix(sb)));
           } else if (i instanceof Number) {
                Number n = (Number) i;

                sb.append(String.format("%s (0x%x)", bolds(bold, String.valueOf(n)), i));
            } else if (i instanceof byte[]) {

                sb.append(boldex(detectPrefix(sb), bold, (byte[]) i));
            } else if (i instanceof TaggedString) {
                TaggedString ts = (TaggedString) i;
             //  sb.append( ts.getId().getClass().getName());
                dump(sb, ts.getId(), true);
                if (ts.tagCount() > 0) {
                    sb.append(" (");
                    for (TaggedString.Attr j : ts.tags()) {
                        String v = j.getValue();
                        String t = j.getAttr();

                        if (t != null) {
                            if (!"desc".equals(t)) {
                                if (v != null) {
                                    sb.append(t);
                                    sb.append(": ");
                                } else {
                                    sb.append("@|underline " + t + "|@");

                                }
                            }
                        }
                        if (v != null)
                            sb.append("@|underline " + v + "|@");

                        sb.append(", ");
                    }
                    sb.setLength(sb.length() - 2);
                    sb.append(")");
                }
            } else {
                bold(bold, sb, i.toString());
            }
        } catch (Exception x) {
            x.printStackTrace();
            sb.append(i);
        }
    }

    private int detectPrefix(StringBuilder sb) {
        int i = sb.length() - 1;
        //while (i >= 0 && sb.charAt(i) != ':') i--;
        int j = i;
        int c = 0;
        int s = 0;
        int si = 0;
        char k;
        while (i >= 0 && (k = sb.charAt(i)) != '\n') {
            switch (k) {
                case '@':
                    if (s == 3) {
                        c += si - i + 1 + 2;
                        s = 0;
                    } else
                        s = 1;
                    break;
                case '|':
                    if (s == 1)
                        s = 2;
                    else if (s == 2)
                        s = 3;
                    break;
                case ' ':
                    if (s == 2)
                        si = i;
                    break;
                default:
                    if (s != 2)
                        s = 0;

            }

            i--;
        }
        if (i < 0)
            return 0;
        return j - i - c;
    }

    private String bolds(boolean bold, String s) {
        if (!bold)
            return s;
        return "@|bold " + s + "|@";
    }

    private String boldex(int detectPrefix, boolean bold, byte[] i) {

        if (i == null)
            return "";
        if (!bold)
            return block(detectPrefix,  16 * 3, ASN1Helper.bytesToHex((byte[]) i, ":"));
        return block(detectPrefix, 4 * 16 * 3, "@|bold " + ASN1Helper.bytesToHex((byte[]) i, "|@:@|bold ") + "|@");
    }

    private String block(int detectPrefix, int linesize, String s) {
        StringBuilder a = new StringBuilder(detectPrefix);
        for (int i = 0; i < detectPrefix; i++) a.append(" ");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length() / linesize; i++) {
            sb.append(s.substring(i * linesize, i * linesize + linesize));
            sb.append("\n");
            sb.append(a);
        }
        sb.append(s.substring((s.length() / linesize) * linesize));

        return sb.toString();
    }

    private void bold(boolean bold, StringBuilder sb, String id) {
        if (!bold)
            sb.append(id);
        else {
            sb.append("@|bold ");
            sb.append(id);
            sb.append("|@");
        }

    }

    private void right(StringBuilder prefix) {
        prefix.append("    ");
    }

    private void left(StringBuilder prefix) {
        prefix.setLength(prefix.length() - 4);
    }


}

