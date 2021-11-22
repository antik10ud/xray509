/*
 * Copyright (c) 2021 David Castañón <antik10ud@gmail.com>
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

package com.k10ud.cli;

import com.k10ud.certs.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class DCRLUtils {

    public static final String DCRL_ETHEREUM = "dcrl:ethereum:";

    static class DCRLContracts {
        byte[] skid;
        List<String> contractAddress;
    }

    static DCRLContracts extractContracts(Context context, byte[] data) {
        Item items = new CertificateProc(context).parse(data);
        QueryCert query = QueryCert.parse("MATCH Extensions/1.3.6.1.4.1.47281.555.1.1/$contracts:=uri, Extensions/2.5.29.14/$skid:=Identifier RETURN $contracts, $skid");
        items = query.project(data, items, new HashMap<>());

        byte[] ski = (byte[]) items.getProp("skid");
        if (ski == null) {
            throw new RuntimeException("subject key identifier not found");
        }


        DCRLContracts r = new DCRLContracts();
        r.skid = ski;
        r.contractAddress = contracts(items.getProp("contracts"));
        return r;
    }

    private static List<String> contracts(Object o) {
        ArrayList<String> list = new ArrayList<>();

        if (o instanceof Item) {

            for (KV i : (Item) o) {
                String contractURI = (String) ((TaggedString) i.getValue()).getId();
                list.add(contractURI);
            }
        } else if (o instanceof String) {
            list.add((String) o);
        }
        return list;
    }


}
