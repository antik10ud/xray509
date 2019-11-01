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

import com.k10ud.asn1.x509_certificate.Extension;
import com.k10ud.asn1.x509_certificate.GeneralSubtree;
import com.k10ud.asn1.x509_certificate.GeneralSubtrees;
import com.k10ud.asn1.x509_certificate.NameConstraints;
import com.k10ud.certs.Context;
import com.k10ud.certs.Item;
import com.k10ud.certs.util.ItemHelper;

import java.io.IOException;

public class NameConstraintsProc extends BaseExtensionProc {

    @Override
    public Item processContent(Context ctx, Extension e) throws IOException {
        Item out = new Item();
        NameConstraints p = new NameConstraints();
        p.decode(e.extnValue.from,e.extnValue.value, true);
        if (p.excludedSubtrees != null)
            out.prop("excluded", subtrees(ctx, p.excludedSubtrees));
        if (p.permittedSubtrees != null)
            out.prop("permitted", subtrees(ctx, p.permittedSubtrees));
        return out;
    }

    private Object subtrees(Context ctx, GeneralSubtrees trees) {
        if (trees == null)
            return Item.EMPTY;
        Item out = new Item();
        if (trees.seqOf != null)
            for (int i = 0, n = trees.seqOf.size(); i < n; i++)
                out.prop(ItemHelper.index( i), subtree(ctx, trees.seqOf.get(i)));
        return out;
    }

    private Object subtree(Context ctx, GeneralSubtree tree) {
        if (tree == null)
            return Item.EMPTY;
        Item out = new Item();
        out.prop("base", ItemHelper.generalName(ctx, tree.base));
        if (tree.maximum != null)
            out.prop("maximum", tree.maximum.getValue());
        if (tree.minimum != null)
            out.prop("minimum", tree.minimum.getValue());
        return out;
    }

}
