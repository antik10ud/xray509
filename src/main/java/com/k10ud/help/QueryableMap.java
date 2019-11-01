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

package com.k10ud.help;

import com.k10ud.certs.Item;
import com.k10ud.certs.KeyDumper;
import com.k10ud.certs.util.ASN1Helper;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

//use query
@Deprecated
public class QueryableMap {
    private final Map<String, Object> map;

    public QueryableMap(Map<String, Object> map) {
        this.map = map;
    }

    public QueryableMap(Item items) {
        this(new KeyDumper().map(items));
    }


    public Map<String,Object> m(String filterGlob) {
        Map<String,Object> list = new LinkedHashMap<>();
        Glob f = new Glob(filterGlob);

        map.forEach((k, v) ->
                {
                    GlobRes gr = f.matcher(k );
                    if (gr.matches()) {
                        list.putIfAbsent(gr.group(1),v);
                    }
                }
        );
        return list;
    }



    public List<String> q(String filterGlob) {
        ArrayList<String> list = new ArrayList<>();
        Glob f = new Glob(filterGlob);

        map.forEach((k, v) ->
                {
                    GlobRes gr = f.matcher(k + "=" + toString(v));
                    if (gr.matches()) {
                        list.add(gr.group(1));
                    }
                }
        );
        return list;
    }

    private String toString(Object v) {
        if (v instanceof byte[])
            return ASN1Helper.bytesToHex((byte[]) v, "");
        return String.valueOf(v);
    }

    public List<String> v(String keyPattern, List<String> keyValues) {
        ArrayList<String> list = new ArrayList<>();

        keyValues.forEach(i -> {
            String k = keyPattern.replaceAll("\\*", i);
            list.add(String.valueOf(map.get(k)));
        });
        return list;
    }

    public Object k(String s) {
        return map.get(s);
    }

    @Override
    public String toString() {
        StringBuilder sb=new StringBuilder();
        map.forEach((k,v)->sb.append(k).append("=").append(v).append("\n"));
        return sb.toString();
    }
}
