
package com.k10ud.certs.util;

import java.io.*;
import java.util.BitSet;

public class BloomFilter {
    private static final byte[] bitvalues = new byte[]{
            (byte) 0x01,
            (byte) 0x02,
            (byte) 0x04,
            (byte) 0x08,
            (byte) 0x10,
            (byte) 0x20,
            (byte) 0x40,
            (byte) 0x80
    };

    private final MurmurHash hash;
    private final BitSet bits;
    private final int vectorSize;
    private final int nbHash;


    /**
     * @param numberOfItems
     * @param falsePositiveProbability 0..1
     */
    public BloomFilter(long numberOfItems, double falsePositiveProbability) {
        double m = Math.ceil((numberOfItems * Math.log(falsePositiveProbability)) / Math.log(1.0 / (Math.pow(2.0, Math.log(2.0)))));
        double k = Math.round(Math.log(2.0) * m / numberOfItems);

        this.vectorSize = ((int) m) + 1;
        this.nbHash = ((int) k) + 1;
        bits = new BitSet(this.vectorSize);
        hash = MurmurHash.getInstance();

    }

    private BloomFilter(int vectorSize, int nbHash) {
        this.vectorSize = vectorSize;
        this.nbHash = nbHash;
        bits = new BitSet(this.vectorSize);
        hash = MurmurHash.getInstance();

    }

    private int[] hash(byte[] b) {
        if (b == null)
            throw new NullPointerException("buffer reference is null");

        int l = b.length;

        if (l == 0)
            throw new IllegalArgumentException("key length must be > 0");

        int[] result = new int[nbHash];
        for (int i = 0, initval = 0; i < nbHash; i++) {
            initval = hash.hash(b, l, initval);
            result[i] = Math.abs(initval % vectorSize);
        }
        return result;
    }


    public void add(byte[] key) {
        if (key == null)
            throw new NullPointerException("key cannot be null");

        int[] h = hash(key);

        for (int i = 0; i < nbHash; i++)
            bits.set(h[i]);

    }

    public boolean test(byte[] key) {
        if (key == null)
            throw new NullPointerException("key cannot be null");


        int[] h = hash(key);
        for (int i = 0; i < nbHash; i++)
            if (!bits.get(h[i]))
                return false;

        return true;
    }

    @Override
    public String toString() {
        return bits.toString();
    }

    public void write(DataOutput out) throws IOException {
        out.writeInt(vectorSize);
        out.writeInt(nbHash);
        byte[] bytes = new byte[getNBytes(vectorSize)];
        for (int i = 0, byteIndex = 0, bitIndex = 0; i < vectorSize; i++, bitIndex++) {
            if (bitIndex == 8) {
                bitIndex = 0;
                byteIndex++;
            }
            if (bitIndex == 0) {
                bytes[byteIndex] = 0;
            }
            if (bits.get(i)) {
                bytes[byteIndex] |= bitvalues[bitIndex];
            }
        }
        out.write(bytes);
    }

    public static BloomFilter read(byte[] in) throws IOException {
        return read(new DataInputStream(new ByteArrayInputStream(in)));
    }

    public static BloomFilter read(DataInput in) throws IOException {
        int vectorSize = in.readInt();
        int nbhash = in.readInt();
        BloomFilter bf = new BloomFilter(vectorSize, nbhash);
        byte[] bytes = new byte[getNBytes(vectorSize)];
        in.readFully(bytes);
        for (int i = 0, byteIndex = 0, bitIndex = 0; i < vectorSize; i++, bitIndex++) {
            if (bitIndex == 8) {
                bitIndex = 0;
                byteIndex++;
            }
            if ((bytes[byteIndex] & bitvalues[bitIndex]) != 0) {
                bf.bits.set(i);
            }
        }
        return bf;
    }

    private static int getNBytes(int vectorSize) {
        return (vectorSize + 7) / 8;
    }

    public byte[] write() {
        try {
            try (ByteArrayOutputStream o0 = new ByteArrayOutputStream();
                 DataOutputStream o = new DataOutputStream(o0)) {
                write(o);
                o0.close();
                return o0.toByteArray();
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
