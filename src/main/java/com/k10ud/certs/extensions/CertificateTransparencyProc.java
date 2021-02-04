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
import com.k10ud.certs.Context;
import com.k10ud.certs.Item;
import com.k10ud.certs.TaggedString;
import com.k10ud.certs.util.ItemHelper;
import org.openmuc.jasn1.ber.types.BerOctetString;

import java.io.IOException;
import java.math.BigInteger;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Date;
import java.util.Stack;

public class CertificateTransparencyProc extends BaseExtensionProc {

    private static class TLSReader {

        private static class W {
            private final int m;

            private W(TLSReader r) {
                this.m = r.m;
            }

            public static W from(TLSReader r) {
                return new W(r);
            }

            public void to(TLSReader r) {
                r.m = this.m;
            }
        }

        private final Stack<W> stack;
        private int p;
        private int m;
        private final byte[] bytes;

        public TLSReader(byte[] bytes) {
            this(bytes, 0, bytes.length);
        }

        public TLSReader(byte[] bytes, int from, int to) {
            this.bytes = bytes;
            this.p = from;
            this.m = to;
            this.stack = new Stack<>();
        }

        public BigInteger uint8() {
            // big-endian binary - ok
            return new BigInteger(1, bytes(8));
        }

        public long int8() {
            return ((0xffl & bytes[incp()]) << 56)
                    | ((0xffl & bytes[incp()]) << 48)
                    | ((0xffl & bytes[incp()]) << 40)
                    | ((0xffl & bytes[incp()]) << 32)
                    | ((0xffl & bytes[incp()]) << 24)
                    | ((0xffl & bytes[incp()]) << 16)
                    | ((0xffl & bytes[incp()]) << 8)
                    | (0xffl & bytes[incp()]);
        }

        public int uint2() {
            return ((0xff & bytes[incp()]) << 8) | (0xff & bytes[incp()]);
        }

        public int uint1() {
            return (0xff & bytes[incp()]);
        }

        private int incp() {
            if (p >= m) {
                throw new RuntimeException("tls struct read out of bounds");
            }
            int k = p;
            p = p + 1;
            return k;
        }


        public TLSReader in(int len) {
            stack.push(W.from(this));
            this.m = p + len;
            return this;
        }

        public TLSReader out() {
            if (stack.isEmpty()) {
                throw new RuntimeException("tls read empty stack");
            }
            stack.pop().to(this);
            return this;
        }

        public byte[] peek() {
            return Arrays.copyOfRange(bytes, p, m);
        }

        public byte[] bytes(int l) {
            if (p + l >= m) {
                throw new RuntimeException("tls cannot read " + l + " bytes");
            }
            byte[] x = Arrays.copyOfRange(bytes, p, p + l);
            p += l;
            return x;
        }


        public TLSReader skip() {
            p = m;
            return this;
        }


        public int rlen() {
            return m - p;
        }
    }

    @Override
    public Item processContent(Context ctx, Extension ext) throws IOException {
        Item out;
        if (ext.extnValue != null) {
            BerOctetString tlsenc = new BerOctetString();
            tlsenc.decode(ext.extnValue.from, ext.extnValue.value);
            out = SignedCertificateTimestampList(ctx, new TLSReader(tlsenc.value));
        } else {
            out = new Item();
        }
        return out;
    }

    private Item SignedCertificateTimestampList(Context ctx, TLSReader r) {
        Item out = new Item();
        /*
            opaque SerializedSCT<1..2^16-1>;

            struct {
                  SerializedSCT sct_list <1..2^16-1>;
            } SignedCertificateTimestampList;
        */
        r.in(r.uint2());

        int i = 0;
        while (r.rlen() > 0) {
            r.in(r.uint2());
            out.prop(ItemHelper.index(i), SerializedSCT(ctx, r));
            r.skip();
            r.out();
            i++;
        }
        r.skip();
        r.out();
        return out;
    }

    private Item SerializedSCT(Context ctx, TLSReader r) {
        /*
            enum { v1(0), (255) }
                Version;

            struct {
               opaque key_id[32];
            } LogID;

            opaque CtExtensions<0..2^16-1>;
            ...

            struct {
               Version sct_version;
               LogID id;
               uint64 timestamp;
               CtExtensions extensions;
               digitally-signed struct {
                   Version sct_version;
                   SignatureType signature_type = certificate_timestamp;
                   uint64 timestamp;
                   LogEntryType entry_type;
                   select(entry_type) {
                       case x509_entry: ASN.1Cert;
                       case precert_entry: PreCert;
                   } signed_entry;
                  CtExtensions extensions;
               };
            } SignedCertificateTimestamp;

            opaque CtExtensions<0..2^16-1>;
        */
        Item out = new Item();
        out.prop("sct_version", version(r.uint1()));
        out.prop("id", r.bytes(32));
        out.prop("timestamp", ZonedDateTime.from(new Date(r.int8()).toInstant().atZone(ZoneOffset.UTC)));
        out.prop("extensions", CtExtensions(ctx, r));
        out.prop("digitally-signed", digitallySigned(ctx, r));
        return out;

    }

    private Item digitallySigned(Context ctx, TLSReader r) {
        /*
            struct {
               SignatureAndHashAlgorithm algorithm;
               opaque signature<0..2^16-1>;
            } DigitallySigned;

            enum {
                none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5),
                sha512(6), (255)
            } HashAlgorithm;

            enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) }
              SignatureAlgorithm;

            struct {
                  HashAlgorithm hash;
                  SignatureAlgorithm signature;
            } SignatureAndHashAlgorithm;
        */
        Item out = new Item();
        out.prop("algorithms", signatureAndHashAlgorithm(ctx, r));
        out.prop("signature", signature(ctx, r));
        return out;
    }

    private Object signature(Context ctx, TLSReader r) {

        return r.peek();
    }


    private Item signatureAndHashAlgorithm(Context ctx, TLSReader r) {
        /*
            struct {
                  HashAlgorithm hash;
                  SignatureAlgorithm signature;
            } SignatureAndHashAlgorithm;

        */
        Item out = new Item();
        out.prop("hash", hashAlgorithm(r.uint1()));
        out.prop("signature", signatureAlgorithm(r.uint1()));
        return out;
    }

    private TaggedString hashAlgorithm(int v) {
        /*
            enum {
                none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5),
                sha512(6), (255)
            } HashAlgorithm;
        */
        TaggedString t = new TaggedString(String.valueOf(v));
        switch (v) {
            case 0:
                t.addTag("none");
                break;
            case 1:
                t.addTag("md5");
                break;
            case 2:
                t.addTag("sha1");
                break;
            case 3:
                t.addTag("sha224");
                break;
            case 4:
                t.addTag("sha256");
                break;
            case 5:
                t.addTag("sha384");
                break;
            case 6:
                t.addTag("sha512");
                break;
        }
        return t;
    }


    private TaggedString signatureAlgorithm(int v) {
        /*
            enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) }
              SignatureAlgorithm;
        */
        TaggedString t = new TaggedString(String.valueOf(v));
        switch (v) {
            case 0:
                t.addTag("anonymous");
                break;
            case 1:
                t.addTag("rsa");
                break;
            case 2:
                t.addTag("dsa");
                break;
            case 3:
                t.addTag("ecdsa");
                break;

        }
        return t;
    }


    private Item CtExtensions(Context ctx, TLSReader r) {
        Item out = new Item();
        r.in(r.uint2());
        int i = 0;
        while (r.rlen() > 0) {
            r.in(r.uint2());
            out.prop(ItemHelper.index(i), r.peek());
            r.skip();
            r.out();
            i++;
        }
        r.skip();
        r.out();
        if (out.size()==0) {
            out.prop("none");
        }
        return out;
    }

    private TaggedString version(int v) {
        TaggedString t = new TaggedString(String.valueOf(v));
        if (v == 0) {
            t.addTag("v1");
        }
        return t;
    }

}