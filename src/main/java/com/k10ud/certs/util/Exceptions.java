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

public class Exceptions {

    public static String getSmartExceptionMessage(Throwable x) {
        // ! not so smart, improve!
        StringBuilder sb = new StringBuilder();
        if (x == null) {
            sb.append("Exception is null");
        } else {

            sb.append(x.getClass().getSimpleName());

            String msg = x.getMessage();
            if (msg != null) {
                sb.append(":");
                sb.append(msg);
            }
            String lastClassName = null;
            for (StackTraceElement i : x.getStackTrace()) {
                String className = i.getClassName();
                if (!className.startsWith("com.k10ud."))
                    continue;

                int di = className.lastIndexOf('.');
                if (di > 0) {
                    className = className.substring(di + 1);
                }
                if (lastClassName == null || !lastClassName.equals(className)) {
                    sb.append("->");
                    sb.append(className);
                    lastClassName = className;
                }
                sb.append(":");
                sb.append(i.getLineNumber());
            }
        }

        return sb.toString();
    }


}
