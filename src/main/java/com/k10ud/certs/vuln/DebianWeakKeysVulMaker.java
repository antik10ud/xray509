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

package com.k10ud.certs.vuln;

import com.k10ud.certs.util.ASN1Helper;
import com.k10ud.certs.util.BloomFilter;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.function.Consumer;
import java.util.stream.Stream;

public class DebianWeakKeysVulMaker{


    //https://www.antoniomallia.it/sorted-integers-compression-with-elias-fano-encoding.html
    //http://mlg.eng.cam.ac.uk/pub/pdf/Ste14.pdf

        public static void main(String[] args) throws IOException {

            Path f = Paths.get("src/test/resources/weakkeys.lst");
            int n = (int) (Files.size(f) / (32 + 1));
            byte[] all = new byte[n * 16];
            double p = 0.01;
            BloomFilter bf = new BloomFilter(n, p);
            // byte[] T = ASN1Helper.hexToBytes("e6:e5:be:ec:63:1c:1e:d2:78:8f:cb:1d:a1:0e:0a:f7");

            try (Stream<String> stream = Files.lines(f)) {
                stream.forEach(
                        new Consumer<String>() {
                            int index = 0;

                            public void accept(String line) {
                                byte[] k = ASN1Helper.hexToBytes(line);


                                bf.add(k);
                                System.arraycopy(k, 0, all, index, k.length);
                                index += 16;
                            }
                        });
            }
            Files.write(Paths.get("src/main/resources/weakkeys.bloom"), bf.write());
            Files.write(Paths.get("src/main/resources/weakkeys.data"), all);
        }


}
