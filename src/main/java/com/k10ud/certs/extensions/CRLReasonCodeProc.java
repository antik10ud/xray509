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

import com.k10ud.asn1.x509_certificate.CRLReason;
import com.k10ud.asn1.x509_certificate.Extension;
import com.k10ud.certs.Context;
import com.k10ud.certs.Item;
import com.k10ud.certs.TaggedString;

import java.io.IOException;

public class CRLReasonCodeProc extends BaseExtensionProc {

    public static TaggedString revocationReason(CRLReason reason) {
        return revocationReason(reason.value);
    }


    private static TaggedString revocationReason(long value) {
/*
  CRLReason ::= ENUMERATED {
        unspecified             (0),
        keyCompromise           (1),
        cACompromise            (2),
        affiliationChanged      (3),
        superseded              (4),
        cessationOfOperation    (5),
        certificateHold         (6),
             -- value 7 is not used
        removeFromCRL           (8),
        privilegeWithdrawn      (9),
        aACompromise           (10) }
 */
        TaggedString ts = new TaggedString(String.valueOf(value));
        switch ("" + value) {
            case "0":
                ts.addTag("unspecified");
                break;
            case "1":
                ts.addTag("keyCompromise");
                break;
            case "2":
                ts.addTag("cACompromise");
                break;
            case "3":
                ts.addTag("affiliationChanged");
                break;
            case "4":
                ts.addTag("superseded");
                break;
            case "5":
                ts.addTag("cessationOfOperation");
                break;
            case "6":
                ts.addTag("certificateHold");
                break;
            case "8":
                ts.addTag("removeFromCRL");
                break;
            case "9":
                ts.addTag("privilegeWithdrawn");
                break;
            case "10":
                ts.addTag("aACompromise");
                break;
        }
        return ts;
    }


    @Override
    public Item processContent(Context ctx, Extension ext) {
        CRLReason reason = new CRLReason();
        Item out = new Item();
        if (ext.extnValue != null) {
            try {
                reason.decode(ext.extnValue.from,ext.extnValue.value, true);
            } catch (IOException e) {
                out.prop("Unable to process data as CRLReason", e);
                out.prop("Raw Value", ext.extnValue);
                return out;
            }
            out.prop("Value",revocationReason(reason));
        }
        return out;
    }

}