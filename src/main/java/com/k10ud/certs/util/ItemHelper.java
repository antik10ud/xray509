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

package com.k10ud.certs.util;

import com.k10ud.asn1.x509_certificate.*;
import com.k10ud.certs.*;
import org.openmuc.jasn1.ber.SourcePostitionable;
import org.openmuc.jasn1.ber.types.BerGeneralizedTime;
import org.openmuc.jasn1.ber.types.BerObjectIdentifier;
import org.openmuc.jasn1.ber.types.BerOctetString;
import org.openmuc.jasn1.ber.types.string.BerBMPString;
import org.openmuc.jasn1.ber.types.string.BerIA5String;

import java.io.IOException;
import java.nio.charset.Charset;
import java.time.Duration;
import java.time.Period;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

public class ItemHelper {
    public static final String RANGEREF = "@rangeref";

    public static Item generalNames(Context ctx, GeneralNames gns) {
        if (gns == null || gns.seqOf.size() == 0)
            return Item.EMPTY;
        Item o = new Item();
        List<GeneralName> seqOf = gns.seqOf;
        for (int i = 0; i < seqOf.size(); i++) {
            GeneralName gn = seqOf.get(i);
            o.prop(ItemHelper.index(i), generalName(ctx, gn, null));
        }
        return o;
    }

    public static Item generalName(Context ctx, GeneralName gn) {
        return generalName(ctx, gn, null);
    }

    public static Item generalName(Context ctx, GeneralName gn, Integer index) {

        if (gn == null)
            return Item.EMPTY;


        if (gn.directoryName != null) {
           /* Item list = new Item();
            gn.directoryName.rdnSequence.seqOf.forEach(i ->
                    i.seqOf.forEach(j ->
                            list.prop(ctx.nameAndOid(j.type), ds(j))
                    ));*/
            return new Item(new TaggedString("directoryName").addIndexTag(index), name(ctx, gn.directoryName));
        }
        if (gn.uniformResourceIdentifier != null) {
            return new Item(new TaggedString("uri").addIndexTag(index), new TaggedString(String.valueOf(gn.uniformResourceIdentifier)).addTag("type", "IA5String"));
        }
        if (gn.dNSName != null) {
            return new Item(new TaggedString("DNSName").addIndexTag(index), new TaggedString(String.valueOf(gn.dNSName)).addTag("type", "IA5String"));
        }
        if (gn.ediPartyName != null) {
            return new Item(new TaggedString("ediPartyName").addIndexTag(index), gn.ediPartyName);
        }
        if (gn.iPAddress != null) {
            return new Item(new TaggedString("IPAddress").addIndexTag(index), new TaggedString(String.valueOf(ipAddress(gn.iPAddress))).addTag("type", "OctetString"));
        }
        if (gn.otherName != null) {
            return new Item(new TaggedString("otherName").addIndexTag(index), gn.otherName);
        }
        if (gn.rfc822Name != null) {
            return new Item(new TaggedString("rfc822Name").addIndexTag(index), new TaggedString(String.valueOf(gn.rfc822Name)).addTag("type", "IA5String"));
        }
        if (gn.x400Address != null) {
            return new Item(new TaggedString("x400Address").addIndexTag(index), gn.x400Address);
        }

        return new Item(new TaggedString("unknown").addIndexTag(index), gn);
    }

    public static Object ipAddress(BerOctetString iPAddress) {
    /*ly for name constraints.  For IPv4
   addresses, the iPAddress field of GeneralName MUST contain eight (8)
   octets, encoded in the style of RFC 4632 (CIDR) to represent an
   address range [RFC4632].  For IPv6 addresses, the iPAddress field
   MUST contain 32 octets similarly encoded.  For example, a name
   constraint for "class C" subnet 192.0.2.0 is represented as the
   octets C0 00 02 00 FF FF FF 00, representing the CIDR notation
   192.0.2.0/24 (mask 255.255.255.0).
*/
        if (iPAddress == null)
            return null;
        byte[] v = iPAddress.value;
        if (v.length == 8) {
            return String.format("%d.%d.%d.%d/%d",
                    v[0], v[1], v[2], v[3],
                    ((v[4] >>> 24) & 0xFF) + ((v[5] >>> 16) & 0xFF) + ((v[6] >>> 8) & 0xFF) + (v[7] >>> 0) & 0xFF
            );
        } else if (iPAddress.value.length == 32) {
            return String.format("%04x:%04x:%04x:%04x/%04x:%04x:%04x:%04x",
                    ((v[0] >>> 24) & 0xFF) + ((v[1] >>> 16) & 0xFF) + ((v[2] >>> 8) & 0xFF) + (v[3] >>> 0) & 0xFF,
                    ((v[4] >>> 24) & 0xFF) + ((v[5] >>> 16) & 0xFF) + ((v[6] >>> 8) & 0xFF) + (v[7] >>> 0) & 0xFF,
                    ((v[8] >>> 24) & 0xFF) + ((v[9] >>> 16) & 0xFF) + ((v[10] >>> 8) & 0xFF) + (v[11] >>> 0) & 0xFF,
                    ((v[12] >>> 24) & 0xFF) + ((v[13] >>> 16) & 0xFF) + ((v[14] >>> 8) & 0xFF) + (v[15] >>> 0) & 0xFF,
                    ((v[16] >>> 24) & 0xFF) + ((v[17] >>> 16) & 0xFF) + ((v[18] >>> 8) & 0xFF) + (v[19] >>> 0) & 0xFF,
                    ((v[20] >>> 24) & 0xFF) + ((v[21] >>> 16) & 0xFF) + ((v[22] >>> 8) & 0xFF) + (v[23] >>> 0) & 0xFF,
                    ((v[24] >>> 24) & 0xFF) + ((v[25] >>> 16) & 0xFF) + ((v[26] >>> 8) & 0xFF) + (v[27] >>> 0) & 0xFF,
                    ((v[28] >>> 24) & 0xFF) + ((v[29] >>> 16) & 0xFF) + ((v[30] >>> 8) & 0xFF) + (v[31] >>> 0) & 0xFF
            );
        }

        return iPAddress;
    }

    public static Item relativeDistinguishedName(Context ctx, RelativeDistinguishedName i, Integer index) {
        if (i == null)
            return Item.EMPTY;
        Item out = new Item();
        for (AttributeTypeAndValue j : i.seqOf) {
            out.prop(ctx.nameAndOid(j.type).addIndexTag(index), ds(j));
        }
        return out;
    }


    //???? -- type!
    public static Object ds(AttributeTypeAndValue j) {
        if (j == null)
            return Item.EMPTY;
        try {

            DirectoryString ds = new DirectoryString();
            ds.decode(j.value.from, j.value.encoded(), null);
            if (ds.bmpString != null)
                return new TaggedString(
                        bmpString(
                                ds.bmpString)).addTag("type", "bmpString");
            else if (ds.printableString != null)
                return new TaggedString(String.valueOf(ds.printableString)).addTag("type", "printableString");
            else if (ds.teletexString != null)
                return new TaggedString(String.valueOf(ds.teletexString)).addTag("type", "teletexString");
            else if (ds.universalString != null)
                return new TaggedString(String.valueOf(ds.universalString)).addTag("type", "universalString");
            else if (ds.utf8String != null)
                return new TaggedString(String.valueOf(ds.utf8String)).addTag("type", "utf8String");

            return ds;
        } catch (IOException e) {
            //cannot decode as Directory String
        }
        try {
            BerIA5String ds = new BerIA5String();
            ds.decode(j.value.from, j.value.value, true);
            return new TaggedString(ds.toString()).addTag("type", "IA5String");
        } catch (IOException e) {
            //cannot decode as BerIA5String
        }
        return j.value;

    }

    public static Object displayText(DisplayText text) {
        if (text == null)
            return Item.EMPTY;
        if (text.bmpString != null)
            return new TaggedString(bmpString(text.bmpString)).addTag("type", "bmpString");
        else if (text.ia5String != null)
            return new TaggedString(String.valueOf(text.ia5String)).addTag("type", "ia5String");
        else if (text.visibleString != null)
            return new TaggedString(String.valueOf(text.visibleString)).addTag("type", "visibleString");
        else if (text.utf8String != null)
            return new TaggedString(String.valueOf(text.utf8String)).addTag("type", "utf8String");
        return text;
    }

    public static Item validity(BerGeneralizedTime notBefore, BerGeneralizedTime notAfter) {
        ZonedDateTime d0 = ASN1Helper.time(notBefore);
        ZonedDateTime d1 = ASN1Helper.time(notAfter);
        return validity(d0, d1, notBefore, notAfter);
    }


    public static Item validity(Time notBefore, Time notAfter) {
        ZonedDateTime d0 = ASN1Helper.time(notBefore);
        ZonedDateTime d1 = ASN1Helper.time(notAfter);
        return validity(d0, d1, notBefore, notAfter);
    }


    private static final int MINUTES_PER_HOUR = 60;
    private static final int SECONDS_PER_MINUTE = 60;
    private static final int SECONDS_PER_HOUR = SECONDS_PER_MINUTE * MINUTES_PER_HOUR;
    private final static ZonedDateTime NO_WELL_DEFINED_EXPIRATION = ZonedDateTime.of(9999, 12, 31, 23, 59, 59, 0, ZoneId.of("Z"));



    public static String duration(BerGeneralizedTime notBefore, BerGeneralizedTime notAfter) {
        ZonedDateTime dd0 = ASN1Helper.time(notBefore);
        ZonedDateTime dd1 = ASN1Helper.time(notAfter);
        return duration(dd0,dd1);
    }


    public static String duration(ZonedDateTime dd0, ZonedDateTime dd1) {
        if (dd0 != null & dd1 != null) {
            Period p = Period.between(dd0.toLocalDate(), dd1.toLocalDate());

            StringBuilder sb = new StringBuilder();
            int y = p.getYears();
            int m = p.getMonths();
            int d = p.getDays();
            if (y > 0) sb.append(String.format(" %d year%s", y, y > 1 ? "s" : ""));
            if (m > 0) sb.append(String.format(" %d month%s", m, m > 1 ? "s" : ""));
            if (d > 0) sb.append(String.format(" %d day%s", d, d > 1 ? "s" : ""));

            Duration du = Duration.between(dd0, dd1);

            long ts = du.getSeconds();
            long tn = du.getNano();

            long h = ts / SECONDS_PER_HOUR;
            int M = (int) ((ts % SECONDS_PER_HOUR) / SECONDS_PER_MINUTE);
            int s = (int) (ts % SECONDS_PER_MINUTE);

            if (h != 0 && h < 24) sb.append(String.format(" %d hour%s", h, h > 1 ? "s" : ""));
            if (M != 0) sb.append(String.format(" %d minute%s", M, M > 1 ? "s" : ""));
            if (s != 0) sb.append(String.format(" %d seconds", s));
            if (tn > 0) sb.append(String.format(" %d nanos", tn));

            if (sb.length() == 0)
                sb.append(" 0");

            return sb.substring(1);
        }
        return "undefined";
    }


    public static Item validity(ZonedDateTime dd0, ZonedDateTime dd1, Object notBefore, Object notAfter) {
        //  LocalDateTime dd0 = d0 == null ? null : LocalDateTime.from(d0.toInstant().atOffset(ZoneOffset.UTC));
        //  LocalDateTime dd1 = d1 == null ? null : LocalDateTime.from(d1.toInstant().atOffset(ZoneOffset.UTC));
        //System.out.println(dd1);
        boolean nwde = NO_WELL_DEFINED_EXPIRATION.compareTo(dd1) == 0;

        Item out = new Item();
        if (dd0 != null & dd1 != null && !nwde) {
            out.prop("Duration", duration(dd0,dd1));
        }
        out.prop("NotBefore", dd0 != null ? dd0 : notBefore);
        TaggedString dd1t = new TaggedString(String.valueOf((dd1 != null ? dd1 : notAfter)));
        if (nwde) {
            dd1t.addTag("No Well Defined Expiration");
        }
        out.prop("NotAfter", dd1t);
        return out;
    }


    private static String bmpString(BerBMPString bmpString) {
        return new String(bmpString.value, Charset.forName("Unicode"));
    }


    public static Item name(Context ctx, Name name) {
        Item out = new Item();
        List<RelativeDistinguishedName> seqOf = name.rdnSequence.seqOf;
        for (int i1 = 0; i1 < seqOf.size(); i1++) {
            RelativeDistinguishedName i = seqOf.get(i1);
            out.transfer(ItemHelper.relativeDistinguishedName(ctx, i, i1));
        }
        return out;
    }

    public static Item algorithms(Context ctx, DigestAlgorithmIdentifiers algorithms) {
        if (algorithms == null)
            return null;
        Item out = new Item();
        List<DigestAlgorithmIdentifier> seqOf = algorithms.seqOf;
        for (int i = 0; i < seqOf.size(); i++) {
            DigestAlgorithmIdentifier identifier = seqOf.get(i);
            out.prop(ItemHelper.index(i), ctx.nameAndOid(identifier.algorithm));
        }
        return out;

    }

    public static Item algorithm(Context context, AlgorithmIdentifier algorithm) {
        if (algorithm == null)
            return null;
        Item out = new Item();
        out.prop("algo", context.nameAndOid(algorithm.algorithm));
        if (algorithm.parameters != null) {
            //The ASN.1 NULL value is represented by two bytes. The tag number is 0x05 and the value associated with the tag, representing the parameter length, is 0x00. Thi
            if ("0500".equals(algorithm.parameters.toString()))
                out.prop("params", "NULL");
            else
                out.prop("params", algorithm.parameters);
        }
        return out;

    }

    public static Item extensions(Context context, Extensions extensions) {
        Item out = new Item();
        List<Extension> seqOf = extensions.seqOf;
        for (int i = 0; i < seqOf.size(); i++) {
            Extension e = seqOf.get(i);
            out.transfer(extension(context, e, i));
        }
        return out;
    }

    ;

    public static Item extension(Context context, Extension extension, Integer index) {
        String oid = extension.extnID.toString();
        Item item = new Item();
   /*     item.prop("OID", context.nameAndOid(oid));
        item.transfer( context.extensionProcessor(oid).process(context, extension));*/
        item.prop(context.nameAndOid(oid).addIndexTag(index), context.extensionProcessor(oid).process(context, extension));

        return item;
    }


    public static Object generalizedTime(BerGeneralizedTime time) {
        return ASN1Helper.time(time);
    }

    public static String index(int i) {
        return "[" + (i) + "]";
    }

    public static Object encoded(Name issuer) {
        if (issuer != null) {
            try {
                issuer.encodeAndSave(1024);
                return issuer.code;
            } catch (IOException e) {
                e.printStackTrace();
            }

        }
        return null;
    }

    public static TaggedString index(int k, String name) {
        return new TaggedString(name).addIndexTag(k);
    }


    public static XPrint xprint(byte[] v) {
        return new XPrint(v);
    }


    public static String cmds_xprint(byte[] bytes, int prefixl) {
        return cmds_xprint(bytes, prefixl, 4);
    }

    public static String cmds_xprint(byte[] bytes, int prefixl, int blocksof8) {
        String data = new String(bytes, Charset.forName("ASCII")).replaceAll("[^\\p{Print}]", " ");
        StringBuilder sb = new StringBuilder();
        StringBuilder prefix = new StringBuilder();

        for (int i = 0; i < prefixl; i++) prefix.append(" ");
        int len = blocksof8 * 8;
        for (int i = 0; i < bytes.length; i += len) {
            if (i > 0) sb.append(prefix);
            sb.append(cmds_xprint(bytes, data, i, blocksof8)).append("\n");
        }
        return sb.toString();
    }

    public static String cmds_xprint(byte[] bytes, String data, int i2, int blocksof8) {
        int n = bytes.length;
        int chunk = blocksof8 * 8;
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("%4s", Integer.toHexString(i2)));
        for (int k = 0, i0 = i2; k < blocksof8 * 2; i0 += 4, k++) {
            if (k % 2 == 0)
                sb.append(" ");
            sb.append(
                    String.format(" %-8s", ASN1Helper.bytesToHex(bytes, i0, 4, ""))
            );
        }
        String text = data.substring(i2, Math.min(data.length(), i2 + chunk));
        sb.append(String.format("  |%-16s|", text));

        return sb.toString();

    }

    public static Item list(Iterator<String> it) {
        Item o = new Item();
        int i = 0;
        while (it.hasNext()) {
            o.prop(index(i), it.next());
            i++;
        }
        return o;
    }


    public static Item withOID(Context ctx, BerObjectIdentifier a, Object out) {
        return new Item(a.toString(), new Item("value", out).prop("desc", ctx.oidName(a.toString())));
    }

    public static void addWithOID(Context ctx, Item out, BerObjectIdentifier berObjectIdentifier) {
        out.prop(berObjectIdentifier.toString(), ctx.oidName(berObjectIdentifier.toString()));

    }

    public static String toHexValue(byte[] source, SourcePostitionable pos) {
        return KeyDumper.toHex(Arrays.copyOfRange(source, (int) pos.getFrom(), (int) pos.getTo()));//!!
    }


}
