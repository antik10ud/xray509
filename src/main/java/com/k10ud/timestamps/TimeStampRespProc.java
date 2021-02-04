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

package com.k10ud.timestamps;

import com.k10ud.asn1.x509_certificate.*;
import com.k10ud.certs.Context;
import com.k10ud.certs.Item;
import com.k10ud.certs.extensions.Flags;
import com.k10ud.certs.util.ItemHelper;
import org.openmuc.jasn1.ber.types.string.BerUTF8String;

import java.io.IOException;


public class TimeStampRespProc {

    private final static Flags failInfoFlags = new Flags(
            new Flags.Bit(0, "badAlg"),
            new Flags.Bit(2, "badRequest"),
            new Flags.Bit(5, "badDataFormat"),
            new Flags.Bit(14, "timeNotAvailable"),
            new Flags.Bit(15, "unacceptedPolicy"),
            new Flags.Bit(16, "unacceptedExtension"),
            new Flags.Bit(17, "addInfoNotAvailable"),
            new Flags.Bit(25, "systemFailure")
    );

    private final Context context;

    public TimeStampRespProc(Context context) {
        this.context = context;
    }

    public Item parse(long offset,byte[] timestampResp) {
        Item out = new Item();
        if (timestampResp == null)
            return out.prop("No Data");

        TimeStampResp tsr = new TimeStampResp();
        try {
            tsr.decode(offset,timestampResp, true);
        } catch (IOException e) {
            out.prop("Unable to process data as TimeStampResp", e);
            out.prop("Raw Value", ItemHelper.xprint(timestampResp));
            return out;
        }

        PKIStatusInfo status = tsr.status;

        if (status != null) {
            out.prop("Status", statusInfo(status));

        }


        TimeStampToken tst = tsr.timeStampToken;
        if (tst != null) {
            out.prop("TimeStampToken", timestampToken(tst));

        }


        return out;

    }

    private Item statusInfo(PKIStatusInfo status) {
        Item item = new Item();
        item.prop("status", status(status.status));
        item.prop("statusString", statusString(status.statusString));
        if (status.failInfo != null)
            item.prop("failInfo", failInfo(status.failInfo));
        return item;
    }

    private String statusString(PKIFreeText text) {
        if (text == null)
            return null;
        StringBuilder sb = new StringBuilder();
        for (BerUTF8String berUTF8String : text.seqOf) {
            sb.append(berUTF8String.toString());
        }
        return sb.toString();

    }

    private Item failInfo(PKIFailureInfo failInfo) {
        return failInfoFlags.in(failInfo);
    }

    private Item status(PKIStatus status) {
        Item i = new Item();
        String name = "unknown";
        try {
            switch (status.getIntExact()) {
                case 0:
                    name = "granted";
                    break;

                case 1:
                    name = "grantedWithMods";
                    break;

                case 2:
                    name = "rejection";
                    break;

                case 3:
                    name = "waiting";
                    break;

                case 4:
                    name = "revocationWarning";
                    break;

                case 5:
                    name = "revocationNotification";
                    break;

            }
        } catch (ArithmeticException x) {
            //unknown code
        }
        i.prop("value",status.getPositiveValue());
        i.prop("desc", name);
        return i;
    }


    private Item timestampToken(TimeStampToken tst) {
        Item item = new Item();
        item.prop("ContentType", context.nameAndOid(tst.contentType));
        switch (tst.contentType.toString()) {
            case "1.2.840.113549.1.7.2":
                SignedData signedData = new SignedData();
                try {
                    signedData.decode(tst.content.from,tst.content.value, true);
                } catch (IOException e) {
                    item.prop("Unable to process data as SignedData", e);
                    item.prop("Raw Value", tst.content);
                }
                item.prop("Content", new SignedDataProc(context).parse(signedData));
                break;
            default:
                item.prop("Content", tst.content);

        }
        return item;
    }

}