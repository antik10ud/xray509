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

/**
 * This class file was automatically generated by jASN1 v1.6.0 (http://www.openmuc.org)
 */

package com.k10ud.asn1.x509_certificate;

import java.io.IOException;
import java.io.EOFException;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.util.List;
import java.util.ArrayList;
import java.util.Iterator;
import java.io.UnsupportedEncodingException;
import org.openmuc.jasn1.ber.*;
import org.openmuc.jasn1.ber.types.*;
import org.openmuc.jasn1.ber.types.string.*;


public class DisplayText implements Encodedable,Decodeable,SourcePostitionable /*1*/ {

public byte[] code = null; public long from,to;
public BerIA5String ia5String = null;

public BerVisibleString visibleString = null;

public BerBMPString bmpString = null;

public BerUTF8String utf8String = null;

public DisplayText() {
}

public DisplayText(byte[] code) {
this.code = code;
}

public DisplayText(BerIA5String ia5String, BerVisibleString visibleString, BerBMPString bmpString, BerUTF8String utf8String) {
this.ia5String = ia5String;
this.visibleString = visibleString;
this.bmpString = bmpString;
this.utf8String = utf8String;
}

public int encode(BerByteArrayOutputStream os, boolean explicit) throws IOException {
if (code != null) {
for (int i = code.length - 1; i >= 0; i--) {
os.write(code[i]);
}
return code.length;

}
int codeLength = 0;
if (utf8String != null) {
codeLength += utf8String.encode(os, true);
return codeLength;

}

if (bmpString != null) {
codeLength += bmpString.encode(os, true);
return codeLength;

}

if (visibleString != null) {
codeLength += visibleString.encode(os, true);
return codeLength;

}

if (ia5String != null) {
codeLength += ia5String.encode(os, true);
return codeLength;

}

throw new IOException("Error encoding BerChoice: No item in choice was selected.");
}

public int decode(long sourceOffset,byte[] bytes, BerIdentifier berIdentifier) throws IOException {
return decode(new CountingInputStream(sourceOffset-(berIdentifier==null?0:(berIdentifier.to-berIdentifier.from)), new ByteArrayInputStream(bytes)), berIdentifier);

}
public int decode(CountingInputStream is, boolean explicit) throws IOException {;

    return decode(is, null);

 };

public int decode(CountingInputStream is, BerIdentifier berIdentifier) throws IOException {
int codeLength = 0;
this.from=is.getPosition()-(berIdentifier==null?0:(berIdentifier.to-berIdentifier.from));
BerIdentifier passedIdentifier = berIdentifier;

if (berIdentifier == null) {
berIdentifier = new BerIdentifier();
codeLength += berIdentifier.decode(is);
}

BerLength length = new BerLength();
if (berIdentifier.equals(BerIA5String.identifier)) {
ia5String = new BerIA5String();
codeLength += ia5String.decode(is, false);
this.to=is.getPosition();
return codeLength;
}

if (berIdentifier.equals(BerVisibleString.identifier)) {
visibleString = new BerVisibleString();
codeLength += visibleString.decode(is, false);
this.to=is.getPosition();
return codeLength;
}

if (berIdentifier.equals(BerBMPString.identifier)) {
bmpString = new BerBMPString();
codeLength += bmpString.decode(is, false);
this.to=is.getPosition();
return codeLength;
}

if (berIdentifier.equals(BerUTF8String.identifier)) {
utf8String = new BerUTF8String();
codeLength += utf8String.decode(is, false);
this.to=is.getPosition();
return codeLength;
}

if (passedIdentifier != null) {
this.to=is.getPosition();
return 0;
}
this.to=is.getPosition();
throw new IOException("Error decoding BerChoice: Identifier matched to no item.");
}

public void encodeAndSave(int encodingSizeGuess) throws IOException {
BerByteArrayOutputStream os = new BerByteArrayOutputStream(encodingSizeGuess);
encode(os, false);
code = os.getArray();
}

public String toString() {
if ( ia5String!= null) {
return "CHOICE{ia5String: " + ia5String + "}";
}

if ( visibleString!= null) {
return "CHOICE{visibleString: " + visibleString + "}";
}

if ( bmpString!= null) {
return "CHOICE{bmpString: " + bmpString + "}";
}

if ( utf8String!= null) {
return "CHOICE{utf8String: " + utf8String + "}";
}

return "unknown";
}

@Override

 public long getFrom() {

     return from;

}

@Override

public long getTo() {

    return to;

}

}

