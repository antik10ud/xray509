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

package com.k10ud.certs;

import java.util.ArrayList;
import java.util.List;

public class TaggedString {


    private Object  id;
    private List<Attr> attrs;


    public static class Attr {
        private final String attr;
        private final String value;

        public Attr(String tag, String value) {
            this.attr = tag;
            this.value = value;
        }

        public Attr(String tag) {
            this.attr = tag;
            this.value = null;
        }

        @Override
        public String toString() {
            return
                    attr +
                            "=" + value;
        }

        public String getAttr() {
            return attr;
        }

        public String getValue() {
            return value;
        }
    }
/*
    public TaggedString(Object main) {
        this(main == null ? null : main.toString());
    }*/

    public TaggedString(Object main) {
        this.id = main;
        attrs = new ArrayList<>();
    }

    public Object getId() {
        return id;
    }

    public TaggedString setId(Object id) {
        this.id = id;
        return this;
    }

    public TaggedString addTag(String tag) {
        attrs.add(new Attr(tag));
        return this;
    }

    public TaggedString addTag(String tag, String value) {
        attrs.add(new Attr(tag, value));
        return this;
    }

    public int tagCount() {
        return attrs.size();
    }

    public Iterable<Attr> tags() {
        return attrs;
    }

    @Override
    public String toString() {
        return id + " (" + attrs + ")";
    }

}
