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
import org.openmuc.jasn1.ber.SourcePostitionable;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

public class KeyDumper implements IItemDumper {


    private final static char[] intToBase16 = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D',
            'E', 'F'};

    private final static int[] base16ToInt = {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, -1, -1, -1, -1, -1, -1, -1, 10, 11, 12, 13, 14, 15, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 10, 11, 12, 13,
            14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1};

    public static String toHex(byte[] bytes) {
        if (bytes == null)
            throw new IllegalArgumentException("null bytes2");
        int n = bytes.length;
        char[] chars = new char[n << 1];
        for (int j = 0; j < n; j++) {
            int v = bytes[j] & 0xFF;
            chars[j << 1] = intToBase16[v >>> 4];
            chars[(j << 1) + 1] = intToBase16[v & 0x0F];
        }
        return new String(chars);
    }


    private static String sep = "/";
    private static String firstsep = "/";
    private byte[] src;

    public String toString(byte[] src, Item item) {
        this.src = src;
        Map<String, Object> map = map(item);
        return toString(map);
    }

    private String toString(Map<String, Object> map) {
        StringBuilder sb = new StringBuilder();
        map.forEach((k, v) -> {
            if (v instanceof SourcePostitionable) {
                SourcePostitionable sp = ((SourcePostitionable) v);
                long from = sp.getFrom();
                long to = sp.getTo();

                sb.append(String.format("%s=[%s..%s)\n", k, from, to));
                if (src != null) {
                    sb.append(String.format("%s______=%s\n", k, toHex(Arrays.copyOfRange(src, (int) from, (int) to))));
                }

            } else {
                sb.append(String.format("%s=%s\n", k, toStringValue(v)));
            }
        });

        return sb.toString();
    }

    private String toStringValue(Object v) {
        if (v instanceof byte[])
            return ASN1Helper.bytesToHex((byte[]) v, "");
        return String.valueOf(v);
    }

    public Map<String, Object> map(Item item) {
        LinkedHashMap<String, Object> map = new LinkedHashMap<>();
        map(firstsep, map, item);
        return map;
    }

    public void map(String prefix, Map<String, Object> map, Item item) {
        for (KV i : item.getProps()) {
            String newprefix = appendPrefix(prefix, keyName(prefix, map, i.key));
            if (i.key instanceof TaggedString) {
                mapAttrs(newprefix, map, (TaggedString)i.key);
            }
            if (i.value != null) {
                if (i.value instanceof Item && ((Item) i.value).size() > 0) {
                    map(newprefix, map, (Item) i.value);
                } else {
                    mapValue(newprefix, map, i.value);
                }
            } else {
                mapput(map, newprefix, null);
            }
        }
    }

    private void mapAttrs(String prefix, Map<String, Object> map, TaggedString key) {
                 for (TaggedString.Attr j : key.tags()) {
                    String v = j.getValue();
                    String t = j.getAttr();
                    if (!t.equalsIgnoreCase("@index")) {
                       map.put(prefix+"/"+t,v);
                    }
                }
            }

    private String keyName(String prefix, Map<String, Object> map, Object key) {
        if (key instanceof TaggedString) {
            TaggedString ts = (TaggedString) key;
            String k = String.valueOf(ts.getId());
            String basePrefix = appendPrefix(prefix, k);
            for (TaggedString.Attr j : ts.tags()) {
                String v = j.getValue();
                String t = j.getAttr();
                if (t.equalsIgnoreCase("@index")) {
                    return ts.getId()+"["+v+"]";
                }
                 }
         /*  for (TaggedString.Attr j : ts.tags()) {
                String v = j.getValue();
                String t = j.getAttr();
                String newprefix = appendPrefix(basePrefix, "@"+t);
                if (v == null)
                    v = "true";
                put(map, newprefix, v);
            }*/
            return k;
        }
        return String.valueOf(key);
    }

    private void mapValue(String prefix, Map<String, Object> map, Object i) {
        if (i == null) {
            mapput(map, prefix, null);
            return;
        }
        try {
            if (i instanceof TaggedString) {
                TaggedString ts = (TaggedString) i;
                mapput(map, prefix, ts.getId());

                if (ts.tagCount() > 0) {

                    for (TaggedString.Attr j : ts.tags()) {

                        String v = j.getValue();
                        String t = j.getAttr();
                        String newprefix = appendPrefix(prefix, "@" + t);
                        if (v == null)
                            v = "true";
                        mapput(map, newprefix, v);
                    }
                }
            } else {
                mapput(map, prefix, i);
            }
        } catch (Exception x) {
            x.printStackTrace();
            //  map.put(prefix,i);
            //  sb.append("{'unprocessable':'" + i + "'}");
        }
    }

    private String appendPrefix(String prefix, String t) {
        return prefix.length() > firstsep.length() ? (prefix + sep + t) : t;


    }

    private void mapput(Map<String, Object> map, String key, Object v) {

        String tk = key;
        int i = 0;
        while (null != map.putIfAbsent(tk, v)) {
            i++;
            tk = key + "[" + i + "]";
        }
        // throw new RuntimeException("Invalid structure: " + key + "=" + v + "\n" + toString(map));
        // System.err.println("Invalid structure: " + key);

    }

}
