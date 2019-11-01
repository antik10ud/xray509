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

package com.k10ud.ocsp;

import com.k10ud.asn1.x509_certificate.*;
import com.k10ud.certs.Context;
import com.k10ud.certs.Item;
import com.k10ud.certs.TaggedString;
import com.k10ud.certs.extensions.CRLReasonCodeProc;
import com.k10ud.certs.util.ItemHelper;

import java.io.IOException;
import java.util.List;


public class OCSPResProc {


    /*





    OCSPResponseStatus ::= ENUMERATED {
        successful            (0),      --Response has valid confirmations
        malformedRequest      (1),      --Illegal confirmation request
        internalError         (2),      --Internal error in issuer
        tryLater              (3),      --Try again later
                                        --(4) is not used
        sigRequired           (5),      --Must sign the request
        unauthorized          (6)       --Request unauthorized
    }

    ResponseBytes ::=       SEQUENCE {
        responseType   OBJECT IDENTIFIER,
        response       OCTET STRING }



    ResponderID ::= CHOICE {
       byName   [1] Name,
       byKey    [2] KeyHash }

    KeyHash ::= OCTET STRING --SHA-1 hash of responder's public key
                             --(excluding the tag and length fields)



     */
    private final Context context;

    public OCSPResProc(Context context) {
        this.context = context;
    }

    /*
    OCSPResponse ::= SEQUENCE {
   responseStatus         OCSPResponseStatus,
   responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL }
     */
    public Item parse(byte[] ocspRes) {
        Item out = new Item();
        if (ocspRes == null)
            return out.prop("No Data");

        OCSPResponse ocspr = new OCSPResponse();
        try {
            ocspr.decode(0,ocspRes, true);
        } catch (IOException e) {
            out.prop("Unable to process data as OCSPResponse", e);
            out.prop("Raw Value", ItemHelper.xprint(ocspRes));
            return out;
        }

        if (ocspr.responseStatus != null)
            out.prop("responseStatus", status(ocspr.responseStatus));
        if (ocspr.responseBytes != null)
            out.prop("responseBytes", bytes(ocspr.responseBytes));

        return out;

    }

    private Item bytes(OCSPResponseBytes bytes) {
        Item out = new Item();
        if (bytes.responseType != null)
            out.prop("type", context.nameAndOid(bytes.responseType));
        if (bytes.response != null) {
            boolean proc = false;
            if (bytes.responseType != null) {
                if ("1.3.6.1.5.5.7.48.1.1".equals(bytes.responseType.toString())) {
                    out.prop("value", ocspResponse(bytes.from,bytes.response.value));
                    proc = true;
                }
            }
            if (!proc)
                out.prop("response", bytes.response);
        }
        return out;
    }


    /*
       BasicOCSPResponse       ::= SEQUENCE {
       tbsResponseData      ResponseData,
       signatureAlgorithm   AlgorithmIdentifier,
       signature            BIT STRING,
       certs                [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }

     */
    private Item ocspResponse(long offset,byte[] value) {
        Item out = new Item();
        BasicOCSPResponse bor = new BasicOCSPResponse();
       /* System.out.println(
                Base64.encodeBytes(value, Base64.DONT_BREAK_LINES)
        );*/
        try {
            //Base64.encodeBytes(value)
            bor.decode(offset,value, true);
        } catch (IOException e) {
            out.prop("Unable to process data as BasicOCSPResponse", e);
            out.prop("Raw Value", bor);
            return out;
        }
        out.prop("tbsResponseData", responseData(bor.tbsResponseData));
        if (bor.signatureAlgorithm != null)
            out.prop("signatureAlgorithm", ItemHelper.algorithm(context, bor.signatureAlgorithm));
        if (bor.signature != null)
            out.prop("signature", bor.signature.value);
        if (bor.certs != null)
            out.prop("certs", OCSPItem.certs(context, bor.certs.seqOf));
        return out;
    }

    /*

    ResponseData ::= SEQUENCE {
       version              [0] EXPLICIT Version DEFAULT v1,
       responderID              ResponderID,
       producedAt               GeneralizedTime,
       responses                SEQUENCE OF SingleResponse,
       responseExtensions   [1] EXPLICIT Extensions OPTIONAL }
     */

    private Item responseData(OCSPResponseData rd) {
        Item out = new Item();
        out.prop("version", OCSPItem.version(rd.version));
        if (rd.responderID != null)
            out.prop("responderID", responderId(rd.responderID));
        if (rd.producedAt != null)
            out.prop("producedAt", ItemHelper.generalizedTime(rd.producedAt));
        if (rd.responses != null)
            out.prop("responses", responses(rd.responses.seqOf));
        if (rd.responseExtensions != null)
            out.prop("responseExtensions", OCSPItem.extensions(context, rd.responseExtensions.seqOf));


        return out;
    }

    private Item responses(List<OCSPSingleResponse> seqOf) {
        Item out = new Item();
        int k = 0;
        for (OCSPSingleResponse i : seqOf)
            out.prop(ItemHelper.index(k++), ocspSingleResponse(i));
        return out;
    }

    /*
        SingleResponse ::= SEQUENCE {
       certID                       CertID,
       certStatus                   CertStatus,
       thisUpdate                   GeneralizedTime,
       nextUpdate           [0]     EXPLICIT GeneralizedTime OPTIONAL,
       singleExtensions     [1]     EXPLICIT Extensions OPTIONAL }


    RevokedInfo ::= SEQUENCE {
        revocationTime              GeneralizedTime,
        revocationReason    [0]     EXPLICIT CRLReason OPTIONAL }
     */
    private Item ocspSingleResponse(OCSPSingleResponse i) {
        Item out = new Item();
        if (i.certID != null)
            out.prop("certID", OCSPItem.certId(context, i.certID));

        if (i.certStatus != null)
            out.prop("certStatus", certStatus(context, i.certStatus));
        return out;
    }

    /*
       CertStatus ::= CHOICE {
            good                [0]     IMPLICIT NULL,
            revoked             [1]     IMPLICIT RevokedInfo,
            unknown             [2]     IMPLICIT UnknownInfo }

     */
    private Item certStatus(Context context, CertStatus certStatus) {
        Item i = new Item();
        if (certStatus.good != null) {
            i.prop("value","good");
        }
        if (certStatus.revoked != null) {
            i.prop("value","revoked");
            i.prop("revokedInfo", revokedInfo(certStatus.revoked));
        }
        if (certStatus.unknown != null) {
            i.prop("value","unknown");
        }

        return i;
    }

    private Item revokedInfo(RevokedInfo revoked) {
        Item i = new Item();
        if (revoked.revocationTime != null) {
            i.prop("revocationTime", ItemHelper.generalizedTime(revoked.revocationTime));
        }
        if (revoked.revocationReason != null) {
            i.prop("revocationReason", CRLReasonCodeProc.revocationReason(revoked.revocationReason));
        }

        return i;
    }



    private Item responderId(OCSPResponderID id) {
        Item out = new Item();
        if (id.byName != null)
            out.prop("byName", ItemHelper.name(context, id.byName));
        if (id.byKey != null)
            out.prop("byKey", id.byKey.value);
        return out;
    }

    /*
        OCSPResponseStatus ::= ENUMERATED {
    successful            (0),      --Response has valid confirmations
    malformedRequest      (1),      --Illegal confirmation request
    internalError         (2),      --Internal error in issuer
    tryLater              (3),      --Try again later
                                    --(4) is not used
    sigRequired           (5),      --Must sign the request
    unauthorized          (6)       --Request unauthorized
}
     */
    private TaggedString status(OCSPResponseStatus status) {
        TaggedString ts = new TaggedString(status.value);
        switch ("" + status.value) {
            case "0":
                ts.addTag("successful");
                break;
            case "1":
                ts.addTag("malformedRequest");
                break;
            case "2":
                ts.addTag("internalError");
                break;
            case "3":
                ts.addTag("tryLater");
                break;
            case "5":
                ts.addTag("sigRequired");
                break;
            case "6":
                ts.addTag("unauthorized");
                break;
        }
        return ts;
    }


}