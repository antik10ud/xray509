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
import com.k10ud.certs.util.ItemHelper;

import java.util.*;

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

    public Map<String, Object> m(String filterGlob) {
        Map<String, Object> list = new LinkedHashMap<>();
        Glob f = new Glob(filterGlob);

        map.forEach((k, v) ->
                {
                    GlobRes gr = f.matcher(k);
                    if (gr.matches()) {
                        list.putIfAbsent(gr.group(1), v);
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
        StringBuilder sb = new StringBuilder();
        map.forEach((k, v) -> sb.append(k).append("=").append(v).append("\n"));
        return sb.toString();
    }

    public byte[] encoded(byte[] src, String s) {
        Object from = map.get(s + "/@src_from");
        Object to = map.get(s + "/@src_to");
        return Arrays.copyOfRange(src, Integer.parseInt(String.valueOf(from)), Integer.parseInt(String.valueOf(to)));
    }

    public byte[] encodedImplicit(byte[] src, String s) {
        Object fromImplicit = map.get(s + "/@src_from_implicit");
        Object to = map.get(s + "/@src_to");
        return Arrays.copyOfRange(src, Integer.parseInt(String.valueOf(fromImplicit)), Integer.parseInt(String.valueOf(to)));
    }
/*
O:3082020a028202010088b0a422b9a1d616217b070d523e8d1879d07d16c54fa2ea2df1d61890f7047030b04f956009c8228e9189e372e72903962a3e6092f7c25b4be71133acc30bd3c0d4f6d5d5cb315a16b63a6dd8d645143d2c554dfc9c2887cab16ed00a536dbed5f1ea00dc7de56c01823a7ec910f623fd2c237c0537f10f025a0dfb447fd10d8ba3b1c8c5b8a433e5a74dba6a1b782bba3bb75a6b0e2b2e63da9e7e2b76b7ffc3367d37cff64e4edaff73c4f2c123ee69a9cb764e8ea967c0f1034506033ca1c380ae59e68fa73c730278e9f065b382387bb06f666a12d8443ada7f47d2427f095172421eb274305daaa2eb468ce30e35d830034cae52cb23b9845023945076870635f13c23730d321c43aea3295f3119677264a92b08212e5f938fefbcabe9381d12f4e1c70beda6e4e87074800b2f956fa73a3d199a0306fb279a8faaae054a97960911a6db16cc42ec188841c172a20c4ab0d6c86a0fe05ab6165ccf41ecf7ee0a2dbfcfa718932681f47abfa8d65d58ef4b2f9277390a68d42bb29324d881bda2ecfa492ffbed5da0873ae658c7d61fce7f7349ab9f1b0567da7794f0eb1a03b2a7b7985fbbc5cc651b42a854ae9a30ad9514aed364e1180c8be436da484a95f4d85cc2fd0bc0e50dde5991a699e3d155c08cf30c1857fc2ce286c47bc3c619c3e89595ca4ac8db7e9d4cf2d491c74af16694e6eedde65ebd60212f239d0203010001
O:3082020a028202010088b0a422b9a1d616217b070d523e8d1879d07d16c54fa2ea2df1d61890f7047030b04f956009c8228e9189e372e72903962a3e6092f7c25b4be71133acc30bd3c0d4f6d5d5cb315a16b63a6dd8d645143d2c554dfc9c2887cab16ed00a536dbed5f1ea00dc7de56c01823a7ec910f623fd2c237c0537f10f025a0dfb447fd10d8ba3b1c8c5b8a433e5a74dba6a1b782bba3bb75a6b0e2b2e63da9e7e2b76b7ffc3367d37cff64e4edaff73c4f2c123ee69a9cb764e8ea967c0f1034506033ca1c380ae59e68fa73c730278e9f065b382387bb06f666a12d8443ada7f47d2427f095172421eb274305daaa2eb468ce30e35d830034cae52cb23b9845023945076870635f13c23730d321c43aea3295f3119677264a92b08212e5f938fefbcabe9381d12f4e1c70beda6e4e87074800b2f956fa73a3d199a0306fb279a8faaae054a97960911a6db16cc42ec188841c172a20c4ab0d6c86a0fe05ab6165ccf41ecf7ee0a2dbfcfa718932681f47abfa8d65d58ef4b2f9277390a68d42bb29324d881bda2ecfa492ffbed5da0873ae658c7d61fce7f7349ab9f1b0567da7794f0eb1a03b2a7b7985fbbc5cc651b42a854ae9a30ad9514aed364e1180c8be436da484a95f4d85cc2fd0bc0e50dde5991a699e3d155c08cf30c1857fc2ce286c47bc3c619c3e89595ca4ac8db7e9d4cf2d491c74af16694e6eedde65ebd60212f239d0203010001

 */

}
