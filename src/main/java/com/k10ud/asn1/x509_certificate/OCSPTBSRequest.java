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


public class OCSPTBSRequest  implements Encodedable,Decodeable,SourcePostitionable /*3*/{

public static class RequestList implements Encodedable,Decodeable,SourcePostitionable /*2*/ {

public static final BerIdentifier identifier = new BerIdentifier(BerIdentifier.UNIVERSAL_CLASS, BerIdentifier.CONSTRUCTED, 16);
protected BerIdentifier id;

public byte[] code = null; public long from, to;
public List<OCSPCertRequest> seqOf = null;

public RequestList() {
id = identifier;
seqOf = new ArrayList<OCSPCertRequest>();
}

public RequestList(byte[] code) {
id = identifier;
this.code = code;
}

public RequestList(List<OCSPCertRequest> seqOf) {
id = identifier;
this.seqOf = seqOf;
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
for (int i = (seqOf.size() - 1); i >= 0; i--) {
codeLength += seqOf.get(i).encode(os, true);
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

while (subCodeLength < totalLength) {
OCSPCertRequest element = new OCSPCertRequest();
subCodeLength += element.decode(is, true);
seqOf.add(element);
}
if (subCodeLength != totalLength) {
throw new IOException("Decoded SequenceOf or SetOf has wrong length. Expected " + totalLength + " but has " + subCodeLength);

}
codeLength += subCodeLength;

this.to=is.getPosition();
return codeLength;
}

public void encodeAndSave(int encodingSizeGuess) throws IOException {
BerByteArrayOutputStream os = new BerByteArrayOutputStream(encodingSizeGuess);
encode(os, false);
code = os.getArray();
}

public String toString() {
StringBuilder sb = new StringBuilder("SEQUENCE OF{");

if (seqOf == null) {
sb.append("null");
}
else {
Iterator<OCSPCertRequest> it = seqOf.iterator();
if (it.hasNext()) {
sb.append(it.next());
while (it.hasNext()) {
sb.append(", ").append(it.next());
}
}
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

public static final BerIdentifier identifier = new BerIdentifier(BerIdentifier.UNIVERSAL_CLASS, BerIdentifier.CONSTRUCTED, 16);
protected BerIdentifier id;

public byte[] code = null; public long from,to;
public OCSPVersion version = null;

public GeneralName requestorName = null;

public RequestList requestList = null;

public Extensions requestExtensions = null;

public OCSPTBSRequest() {
id = identifier;
}

public OCSPTBSRequest(byte[] code) {
id = identifier;
this.code = code;
}

public OCSPTBSRequest(OCSPVersion version, GeneralName requestorName, RequestList requestList, Extensions requestExtensions) {
id = identifier;
this.version = version;
this.requestorName = requestorName;
this.requestList = requestList;
this.requestExtensions = requestExtensions;
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

if (requestExtensions != null) {
sublength = requestExtensions.encode(os, true);
codeLength += sublength;
codeLength += BerLength.encodeLength(os, sublength);
// write tag: CONTEXT_CLASS, CONSTRUCTED, 2
os.write(0xa2);
codeLength += 1;
}

codeLength += requestList.encode(os, true);

if (requestorName != null) {
sublength = requestorName.encode(os, true);
codeLength += sublength;
codeLength += BerLength.encodeLength(os, sublength);
// write tag: CONTEXT_CLASS, CONSTRUCTED, 1
os.write(0xa1);
codeLength += 1;
}

if (version != null) {
sublength = version.encode(os, true);
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

subCodeLength += berIdentifier.decode(is);
if (berIdentifier.equals(BerIdentifier.CONTEXT_CLASS, BerIdentifier.CONSTRUCTED, 0)) {
subCodeLength += length.decode(is);
version = new OCSPVersion();
subCodeLength += version.decode(is, true);
subCodeLength += berIdentifier.decode(is);
}

if (berIdentifier.equals(BerIdentifier.CONTEXT_CLASS, BerIdentifier.CONSTRUCTED, 1)) {
subCodeLength += length.decode(is);
requestorName = new GeneralName();
subCodeLength += requestorName.decode(is, null);
subCodeLength += berIdentifier.decode(is);
}

if (berIdentifier.equals(RequestList.identifier)) {
requestList = new RequestList();
subCodeLength += requestList.decode(is, false);
if (subCodeLength == totalLength) {
this.to=is.getPosition();
return codeLength;
}
subCodeLength += berIdentifier.decode(is);
}
else {
throw new IOException("Identifier does not match the mandatory sequence element identifer.");
}

if (berIdentifier.equals(BerIdentifier.CONTEXT_CLASS, BerIdentifier.CONSTRUCTED, 2)) {
subCodeLength += length.decode(is);
requestExtensions = new Extensions();
subCodeLength += requestExtensions.decode(is, true);
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
if (version != null) {
sb.append("version: ").append(version);
firstSelectedElement = false;
}

if (requestorName != null) {
if (!firstSelectedElement) {
sb.append(", ");
}
sb.append("requestorName: ").append(requestorName);
firstSelectedElement = false;
}

if (!firstSelectedElement) {
sb.append(", ");
}
sb.append("requestList: ").append(requestList);

if (requestExtensions != null) {
sb.append(", ");
sb.append("requestExtensions: ").append(requestExtensions);
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

