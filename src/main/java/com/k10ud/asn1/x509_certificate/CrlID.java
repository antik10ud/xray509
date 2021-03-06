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


public class CrlID  implements Encodedable,Decodeable,SourcePostitionable /*3*/{

public static final BerIdentifier identifier = new BerIdentifier(BerIdentifier.UNIVERSAL_CLASS, BerIdentifier.CONSTRUCTED, 16);
protected BerIdentifier id;

public byte[] code = null; public long from,to;
public BerIA5String crlUrl = null;

public BerInteger crlNum = null;

public BerGeneralizedTime crlTime = null;

public CrlID() {
id = identifier;
}

public CrlID(byte[] code) {
id = identifier;
this.code = code;
}

public CrlID(BerIA5String crlUrl, BerInteger crlNum, BerGeneralizedTime crlTime) {
id = identifier;
this.crlUrl = crlUrl;
this.crlNum = crlNum;
this.crlTime = crlTime;
}

public int encode(BerByteArrayOutputStream os, boolean explicit) throws IOException {

int codeLength;

if (code != null) {
codeLength = code.length;
for (int i = code.length - 1; i >= 0; i--) {
os.write(code[i]);
}
}
else {
codeLength = 0;
int sublength;

if (crlTime != null) {
sublength = crlTime.encode(os, true);
codeLength += sublength;
codeLength += BerLength.encodeLength(os, sublength);
// write tag: CONTEXT_CLASS, CONSTRUCTED, 2
os.write(0xa2);
codeLength += 1;
}

if (crlNum != null) {
sublength = crlNum.encode(os, true);
codeLength += sublength;
codeLength += BerLength.encodeLength(os, sublength);
// write tag: CONTEXT_CLASS, CONSTRUCTED, 1
os.write(0xa1);
codeLength += 1;
}

if (crlUrl != null) {
sublength = crlUrl.encode(os, true);
codeLength += sublength;
codeLength += BerLength.encodeLength(os, sublength);
// write tag: CONTEXT_CLASS, CONSTRUCTED, 0
os.write(0xa0);
codeLength += 1;
}

codeLength += BerLength.encodeLength(os, codeLength);
}

if (explicit) {
codeLength += id.encode(os);
}

return codeLength;
}

public int decode(long sourceOffset,byte[] bytes, boolean explicit) throws IOException {
return decode(new CountingInputStream(sourceOffset,new ByteArrayInputStream(bytes)), explicit);

}
public int decode(CountingInputStream is, boolean explicit) throws IOException {
int codeLength = 0;
this.from=is.getPosition();
int subCodeLength = 0;
BerIdentifier berIdentifier = new BerIdentifier();

if (explicit) {
codeLength += id.decodeAndCheck(is);
}

BerLength length = new BerLength();
codeLength += length.decode(is);

int totalLength = length.val;
codeLength += totalLength;

if (totalLength == 0) {
this.to=is.getPosition();
return codeLength;
}
subCodeLength += berIdentifier.decode(is);
if (berIdentifier.equals(BerIdentifier.CONTEXT_CLASS, BerIdentifier.CONSTRUCTED, 0)) {
subCodeLength += length.decode(is);
crlUrl = new BerIA5String();
subCodeLength += crlUrl.decode(is, true);
if (subCodeLength == totalLength) {
this.to=is.getPosition();
return codeLength;
}
subCodeLength += berIdentifier.decode(is);
}

if (berIdentifier.equals(BerIdentifier.CONTEXT_CLASS, BerIdentifier.CONSTRUCTED, 1)) {
subCodeLength += length.decode(is);
crlNum = new BerInteger();
subCodeLength += crlNum.decode(is, true);
if (subCodeLength == totalLength) {
this.to=is.getPosition();
return codeLength;
}
subCodeLength += berIdentifier.decode(is);
}

if (berIdentifier.equals(BerIdentifier.CONTEXT_CLASS, BerIdentifier.CONSTRUCTED, 2)) {
subCodeLength += length.decode(is);
crlTime = new BerGeneralizedTime();
subCodeLength += crlTime.decode(is, true);
if (subCodeLength == totalLength) {
this.to=is.getPosition();
return codeLength;
}
}
throw new IOException("Unexpected end of sequence, length tag: " + totalLength + ", actual sequence length: " + subCodeLength);


}

public void encodeAndSave(int encodingSizeGuess) throws IOException {
BerByteArrayOutputStream os = new BerByteArrayOutputStream(encodingSizeGuess);
encode(os, false);
code = os.getArray();
}

public String toString() {
StringBuilder sb = new StringBuilder("SEQUENCE{");
boolean firstSelectedElement = true;
if (crlUrl != null) {
sb.append("crlUrl: ").append(crlUrl);
firstSelectedElement = false;
}

if (crlNum != null) {
if (!firstSelectedElement) {
sb.append(", ");
}
sb.append("crlNum: ").append(crlNum);
firstSelectedElement = false;
}

if (crlTime != null) {
if (!firstSelectedElement) {
sb.append(", ");
}
sb.append("crlTime: ").append(crlTime);
firstSelectedElement = false;
}

sb.append("}");
return sb.toString();
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

