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

package com.k10ud.cli;

import com.k10ud.certs.Item;
import com.k10ud.certs.KV;
import com.k10ud.certs.TaggedString;
import com.k10ud.x509ql.X509qlLexer;
import com.k10ud.x509ql.X509qlListener;
import com.k10ud.x509ql.X509qlParser;
import org.antlr.v4.runtime.CharStreams;
import org.antlr.v4.runtime.CodePointCharStream;
import org.antlr.v4.runtime.CommonTokenStream;
import org.antlr.v4.runtime.tree.ParseTree;
import org.antlr.v4.runtime.tree.ParseTreeWalker;

import java.util.*;

public class QueryCert {

    public static class Return {
        String variable;
        String fieldName;
        String prop;
    }

    public static class Prop {
        String prop;
        String value;
    }

    public static class ValueFilter {
        String value;
        List<Prop> props = new ArrayList<>();
    }

    public static class Selector {
        String expr;
        List<Prop> props = new ArrayList<>();
        ValueFilter value;
        String variable;

        public boolean matches(KV kv) {
            if (!matchstr(expr, value(kv.getKey())))
                return false;
            if (props != null && props.size() > 0) {
                if (!matchProps(props, kv.getKey()))
                    return false;
            }
            if (value != null) {
                if (!matchstr(value.value, value(kv.getValue())))
                    return false;
                if (!matchProps(value.props, kv.getValue()))
                    return false;

            }
            return true;
        }

        private boolean matchstr(String expr, String value) {
            if (expr == null)
                return true;
            if ("*".equals(expr))
                return true;
            if ("**".equals(expr))
                return true;

            Glob2 re = new Glob2(expr);
            return re.matcher(value).matches();
        }

        private boolean matchProps(List<Prop> props, Object k) {
            if (props == null || props.size() == 0)
                return true;


            int match = 0;
            for (Prop p : props) {
                if ("*".equals(p.prop))
                    continue;

                if (!(k instanceof TaggedString)) {
                    return false;
                }
                TaggedString ts = (TaggedString) k;
                Iterator<TaggedString.Attr> iterator = ts.tags().iterator();
                while (iterator.hasNext()) {
                    TaggedString.Attr attr = iterator.next();
                    if (matchstr(p.prop, attr.getAttr())) {
                        if (matchstr(p.value, attr.getValue())) {
                            match++;
                        }
                    }
                }

            }
            return match == props.size();
        }

        private String value(Object key) {
            if (key instanceof String) {
                return (String) key;
            }
            if (key instanceof TaggedString) {
                return String.valueOf(((TaggedString) key).getId());
            }
            return String.valueOf(key);
        }

    }

    public static class Segments {
        public String variable;
        public boolean required;
        List<Selector> selectors = new ArrayList<>();


    }

    List<Segments> select = new ArrayList<>();
    List<Return> returns = new ArrayList<>();

    public static QueryCert parse(String query) {
        CodePointCharStream input = CharStreams.fromString(query);
        X509qlLexer lexer = new X509qlLexer(input);
        CommonTokenStream tokens = new CommonTokenStream(lexer);
        X509qlParser parser = new X509qlParser(tokens);
        ParseTree tree = parser.root();
        ParseTreeWalker walker = new ParseTreeWalker();
        QueryCert qc = new QueryCert();
        X509qlListener listener = new MyX509qlListener(input, qc);
        walker.walk(listener, tree);
        return qc;
    }


    public void addSelect(Segments expression) {
        select.add(expression);
    }


    public boolean match(Item parse) {
        return true;
    }

    public boolean hasProjection() {
        return select.size() > 0;
    }

    static class VarHolder {
        Map<String, KV> vars = new HashMap<>();

        public void add(String variable, KV kv) {
            vars.put(variable, kv);
        }

        public KV getVar(String variable) {
            return vars.get(variable);
        }

        public void addAll(HashMap<String, String> ctx) {
            for (Map.Entry<String, String> i : ctx.entrySet()) {
                vars.put(i.getKey(), new KV(i.getKey(), i.getValue()));

            }
        }

        public Object getVarValue(String s) {
            KV i = vars.get(s);
            if (i == null)
                return null;
            return i.getValue();
        }
    }

    public Item project(Item items, HashMap<String, String> ctx) {
        Item output = new Item();
        VarHolder vars = new VarHolder();
        vars.addAll(ctx);
        for (Segments i : select) {
            List<KV> kv = new ArrayList<>();
            search("", items, 0, i.selectors, kv, vars);
            if (kv != null && kv.size() > 0) {
                output.addAll(kv);
            } else {
                if (i.required) {
                    return new Item();
                }
            }
        }

        /*if (output.size() == 0) {
            return new Item();
        }*/
        if (returns.size() > 0) {
            return returnItems(vars);
        }
        return output;
    }

    private Item returnItems(VarHolder vars) {
        Item output = new Item();

        for (Return r : returns) {
            Object value = null;
            KV kv = null;
            String var = r.variable;
            if (var.startsWith("$ctx.")) {
                String v = var.substring(5);
                value = vars.getVarValue("ξ" + v);
            } else {
                kv = vars.getVar(var);
                if (kv != null) {
                    if (r.prop != null) {
                        switch (r.prop) {
                            case "ξvalue":
                                Object v = kv.getValue();
                                if (v instanceof String) {
                                    value = (String) v;
                                } else if (v instanceof TaggedString) {
                                    value = String.valueOf(((TaggedString) v).getId());
                                } else {
                                    value = String.valueOf(v);//.replaceAll("\n","");
                                }
                                break;
                            case "ξkey":
                                value = kv.getKey();
                                break;
                            default:
                                if (kv.getValue() instanceof TaggedString) {
                                    TaggedString ts = (TaggedString) (kv.getValue());
                                    Iterator<TaggedString.Attr> iterator = ts.tags().iterator();
                                    while (iterator.hasNext()) {
                                        TaggedString.Attr attr = iterator.next();
                                        if (r.prop.equalsIgnoreCase(attr.getAttr())) {
                                            value = attr.getValue();
                                            break;
                                        }
                                    }
                                }
                        }
                    } else {
                        Object v = kv.getValue();
                        if (v instanceof String) {
                            value = (String) v;
                        } else if (v instanceof TaggedString) {
                            value = String.valueOf(((TaggedString) v).getId());
                        } else {
                            value = v;//String.valueOf(v);
                        }
                    }
                }
                if (value == null) {
                    value = "<NULL>";
                }
            }
            output.add(new KV(fieldName(r, kv), value));


        }

        return output;
    }

    private String fieldName(Return r, KV kv) {
        String fieldName = r.fieldName;
        if (fieldName != null && kv != null) {
            switch (fieldName) {
                case "ξpath":
                    return kv.getKey().toString();
            }
        }
        return fieldName != null && fieldName.length() > 0 ? fieldName : varAsFieldName(r);
    }

    private String varAsFieldName(Return r) {
        return r.variable.substring(1) + (r.prop != null && !r.prop.startsWith("ξ") ? "_" + r.prop : "");
    }


    private void search(String path, Item items, int index, List<Selector> selectors, List<KV> list, VarHolder vars) {
        if (index >= selectors.size()) {
            return;
        }
        Selector key = selectors.get(index);
        List<KV> candidates;
        boolean indepth = false;
        String variable = null;
        if (key.expr != null && key.expr.equalsIgnoreCase("**")) {
            candidates = new ArrayList<>();
            searchAnyDepth("", items, makeDeepSelector(index, selectors, key), candidates);
            index = index + 1;
            if (index < selectors.size()) {
                variable = selectors.get(index).variable;
            }
            indepth = true;
        } else {
            candidates = items.getProps();
            variable = key.variable;
        }
        for (KV kv : candidates) {
            if (indepth || key.matches(kv)) {

                if (variable != null) {
                    vars.add(variable, kv.copyAs(path + "/" + kv.getKey()));
                }

                if (index + 1 < selectors.size()) {
                    if (kv.getValue() instanceof Item) {
                        search(path + "/" + kv.getKey(), (Item) kv.getValue(), index + 1, selectors, list, vars);
                    }
                } else {
                    KV kvc = kv.copyAs(path + "/" + kv.getKey());
                    list.add(kvc);
                }
            }
        }

    }

    private Selector makeDeepSelector(int index, List<Selector> selectors, Selector key) {
        Selector s = new Selector();
        if (index + 1 < selectors.size()) {
            s.expr = selectors.get(index + 1).expr;
            s.props = key.props;
            s.value = key.value;
        } else {
            s.expr = "*";
            s.props = key.props;
            s.value = key.value;
        }
        return s;
    }

    private void searchAnyDepth(String path, Item items, Selector selector, List<KV> list) {
        for (KV kv : items.getProps()) {
            if (selector.matches(kv)) {
                KV kvc = kv.copyAs(makePath(path, kv));
                list.add(kvc);
            }
            if (kv.getValue() instanceof Item) {
                searchAnyDepth(makePath(path, kv), (Item) kv.getValue(), selector, list);
            }
        }
    }

    private String makePath(String path, KV kv) {
        return (path.length() == 0 ? "" : path + "/") + keyname(kv.getKey());
    }

    private String keyname(Object key) {

        if (key instanceof String) {
            return (String) key;
        }

        return String.valueOf(key);

    }


}
