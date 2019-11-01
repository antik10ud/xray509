

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

import com.bakkenbaeck.token.crypto.cryptohash.Keccak256;
import com.k10ud.asn1.x509_certificate.*;
import org.openmuc.jasn1.ber.types.BerGeneralizedTime;
import org.openmuc.jasn1.ber.types.string.BerIA5String;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.SimpleTimeZone;

public class ASN1Helper {

    public static final SimpleDateFormat DF_yyyyMMddHHmmssz = new SimpleDateFormat("yyyyMMddHHmmssz");
    public static final SimpleDateFormat DF_yyyyMMddHHmmss_SSSZ = new SimpleDateFormat("yyyyMMddHHmmss.SSS'Z'");
    public static final SimpleDateFormat DF_yyyyMMddHHmmssZ = new SimpleDateFormat("yyyyMMddHHmmss'Z'");
    public static final SimpleDateFormat DF_yyyyMMddHHmmss_SSSz = new SimpleDateFormat("yyyyMMddHHmmss.SSSz");
    public static final SimpleDateFormat DF_yyyyMMddHHmmss_SSS = new SimpleDateFormat("yyyyMMddHHmmss.SSS");
    public static final SimpleDateFormat DF_yyyyMMddHHmmss = new SimpleDateFormat("yyyyMMddHHmmss");
    public static final SimpleTimeZone Z_TIME_ZONE = new SimpleTimeZone(0, "Z");

    static {
        DF_yyyyMMddHHmmssz.setTimeZone(Z_TIME_ZONE);
        DF_yyyyMMddHHmmss_SSSZ.setTimeZone(Z_TIME_ZONE);
        DF_yyyyMMddHHmmssZ.setTimeZone(Z_TIME_ZONE);
        DF_yyyyMMddHHmmss_SSSz.setTimeZone(Z_TIME_ZONE);
        DF_yyyyMMddHHmmss.setTimeZone(Z_TIME_ZONE);

    }

    //borrowed from bc, smells, review
    public static ZonedDateTime time(Time t) {
        if (t == null)
            return null;
        if (t.generalTime != null) {
            return time(t.generalTime);
        }

        if (t.utcTime != null) {
            String time = toString(t.utcTime.value);
            if (time.indexOf('-') < 0 && time.indexOf('+') < 0) {
                if (time.length() == 11)
                    time = time.substring(0, 10) + "00GMT+00:00";
                else
                    time = time.substring(0, 12) + "GMT+00:00";
            } else {
                int index = time.indexOf('-');
                if (index < 0)
                    index = time.indexOf('+');
                String d = time;

                if (index == time.length() - 3)
                    d += "00";

                if (index == 10)
                    time = d.substring(0, 10) + "00GMT" + d.substring(10, 13) + ":" + d.substring(13, 15);
                else
                    time = d.substring(0, 12) + "GMT" + d.substring(12, 15) + ":" + d.substring(15, 17);
            }
            if (time.charAt(0) < '5')
                time = "20" + time;
            else
                time = "19" + time;
            try {
                return ZonedDateTime.from(DF_yyyyMMddHHmmssz.parse(time).toInstant().atOffset(ZoneOffset.UTC));
            } catch (ParseException e) {
                return null;
            }
        }
        return null;
    }

    public static ZonedDateTime time(BerGeneralizedTime generalTime) {
        if (generalTime == null)
            return null;
        String time = toString(generalTime.value);
        boolean hasFractionalSeconds = time.indexOf('.') == 14;
        SimpleDateFormat dateF;
        if (time.endsWith("Z")) {
            if (hasFractionalSeconds)
                dateF = DF_yyyyMMddHHmmss_SSSZ;
            else
                dateF = DF_yyyyMMddHHmmssZ;

        } else if (time.indexOf('-') > 0 || time.indexOf('+') > 0) {
            if (hasFractionalSeconds)
                dateF = DF_yyyyMMddHHmmss_SSSz;
            else
                dateF = DF_yyyyMMddHHmmssz;
        } else {
            if (hasFractionalSeconds)
                dateF = DF_yyyyMMddHHmmss_SSS;
            else
                dateF = DF_yyyyMMddHHmmss;
        }
        if (hasFractionalSeconds) {
            // java misinterprets extra digits as being milliseconds...
            String frac = time.substring(14);
            int index;
            for (index = 1; index < frac.length(); index++) {
                char ch = frac.charAt(index);
                if (!('0' <= ch && ch <= '9'))
                    break;
            }
            if (index - 1 > 3) {
                frac = frac.substring(0, 4) + frac.substring(index);
                time = time.substring(0, 14) + frac;
            } else if (index - 1 == 1) {
                frac = frac.substring(0, index) + "00" + frac.substring(index);
                time = time.substring(0, 14) + frac;
            } else if (index - 1 == 2) {
                frac = frac.substring(0, index) + "0" + frac.substring(index);
                time = time.substring(0, 14) + frac;
            }
        }
        try {
            return ZonedDateTime.from(dateF.parse(time).toInstant().atZone(ZoneOffset.UTC));
        } catch (ParseException e) {
            return null;
        }


    }


    public static String toString(byte[] bytes) {
        char[] dateC = new char[bytes.length];
        for (int i = 0; i != dateC.length; i++)
            dateC[i] = (char) (bytes[i] & 0xff);
        return new String(dateC);

    }

    public static String bytesToHex(final byte[] bytes, String sep) {
        if (bytes == null || bytes.length == 0)
            return "";
        return bytesToHex(bytes, 0, bytes.length, sep);
    }

    public static String bytesToHex(final byte[] bytes, int o, int l, String sep) {
        int bl = bytes.length;
        if (bytes == null || bl == 0)
            return "";
        int sl = sep.length();
        StringBuilder sb = new StringBuilder(l * (sl + 2) + sl);
        for (int i = o; i < o + l && i < bl; i++) {
            byte v = bytes[i];
            sb.append(String.format("%02x", v & 0xff));
            sb.append(sep);
        }
        sb.setLength(sb.length() - sl);
        return sb.toString();
    }

    public static byte[] hash(String hash, byte[] data) {
        if (data==null)
            return new byte[0];
        if ("SHA3-256".equals(hash) || "2.16.840.1.101.3.4.2.8".equals(hash)) {
            Keccak256 keccak256 = new Keccak256();
            byte[] sha3 = keccak256.digest(data);
            return sha3;
        }
        MessageDigest calculator;
        try {
            calculator = MessageDigest.getInstance(hash);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return new byte[]{};
        }
        return calculator.digest(data);
    }

    public static byte[] hexToBytes(String messageImprint) {
        if (messageImprint == null)
            return new byte[0];
        String s = messageImprint.toUpperCase().replaceAll("[^ABCDEFX01234567890]", "");
        if (s.startsWith("0X"))
            s = s.substring(2);
        s = s.replaceAll("X", "");
        int len = s.length();
        if (len % 2 == 1)
            throw new IllegalArgumentException("Invalid hex value");

        byte[] data = new byte[len >> 1];
        for (int i = 0; i < len; i += 2) {
            data[i >> 1] = (byte) (
                    (Character.digit(s.charAt(i), 16) << 4)
                            + Character.digit(s.charAt(i + 1), 16)
            );
        }
        return data;
    }

    public static int[] intArray(String salg) {
        String[] t = salg.split("\\.");
        int[] v = new int[t.length];
        int j = 0;
        for (String i : t) {
            v[j++] = Integer.parseInt(i);
        }
        return v;
    }

    public static String generalNames(GeneralNames gns) {
        if (gns == null || gns.seqOf.size() == 0)
            return "";
        StringBuilder sb = new StringBuilder();
        List<GeneralName> seqOf = gns.seqOf;
        for (int i = 0; i < seqOf.size(); i++) {
            if (i > 0)
                sb.append(",");
            GeneralName gn = seqOf.get(i);
            sb.append(generalName(gn));
        }
        return sb.toString();
    }

    public static String generalName(GeneralName gn) {
        if (gn == null)
            return "";
        if (gn.directoryName != null) {
            return new String(rdns(gn.directoryName.rdnSequence.seqOf));


        }
        if (gn.uniformResourceIdentifier != null) {
            return new String(gn.uniformResourceIdentifier.value);
        }
        if (gn.dNSName != null) {
            return new String(gn.dNSName.value);
        }
        if (gn.ediPartyName != null) {
            return new String(gn.ediPartyName.toString());
        }
        if (gn.iPAddress != null) {
            return new String(gn.iPAddress.value);
        }
        if (gn.otherName != null) {
            return new String(gn.otherName.toString());
        }
        if (gn.rfc822Name != null) {
            return new String(gn.rfc822Name.value);
        }
        if (gn.x400Address != null) {
            return new String(gn.x400Address.toString());
        }

        return "";
    }

    private static String rdns(List<RelativeDistinguishedName> seqOf) {
        ArrayList<String> list = new ArrayList<>();
        seqOf.forEach(i ->
                i.seqOf.forEach(j ->
                        list.add(j.type.toString() + "=" + ds(j))
                ));
        Collections.sort(list);
        StringBuilder sb = new StringBuilder();
        for (int i1 = 0; i1 < list.size(); i1++) {
            if (i1 > 0)
                sb.append(",");
            String i = list.get(i1);
            sb.append(i);
        }
        return sb.toString();
    }

    public static String ds(AttributeTypeAndValue j) {
        if (j == null)
            return "";
        try {

            DirectoryString ds = new DirectoryString();
            ds.decode(j.value.from,j.value.value, null);
            if (ds.bmpString != null)
                return ds.bmpString.toString();
            else if (ds.printableString != null)
                return ds.printableString.toString();
            else if (ds.teletexString != null)
                return ds.teletexString.toString();
            else if (ds.universalString != null)
                return ds.universalString.toString();
            else if (ds.utf8String != null)
                return ds.utf8String.toString();


        } catch (IOException e) {
            //cannot decode as Directory String
        }
        try {
            BerIA5String ds = new BerIA5String();
            ds.decode(j.value.from,j.value.value, true);
            return ds.toString();
        } catch (IOException e) {
            //cannot decode as BerIA5String
        }
        if (j.value == null)
            return "";
        return j.value.toString();

    }

    public static String name(Name subject) {
        if (subject == null || subject.rdnSequence == null)
            return "";

        return rdns(subject.rdnSequence.seqOf);
    }


}
