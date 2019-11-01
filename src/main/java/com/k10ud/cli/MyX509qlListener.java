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

import com.k10ud.x509ql.X509qlListener;
import com.k10ud.x509ql.X509qlParser;
import org.antlr.v4.runtime.CharStream;
import org.antlr.v4.runtime.ParserRuleContext;
import org.antlr.v4.runtime.tree.ErrorNode;
import org.antlr.v4.runtime.tree.TerminalNode;

import java.util.ArrayList;
import java.util.List;

class MyX509qlListener implements X509qlListener {
    private final CharStream input;
    private final QueryCert qc;

    public MyX509qlListener(CharStream input, QueryCert qc) {
        this.input = input;
        this.qc = qc;
    }


    @Override
    public void exitReturnElements(X509qlParser.ReturnElementsContext ctx) {
        ctx.returnElement().forEach(i -> qc.returns.add(processReturnElement(i)));

    }

    private QueryCert.Return processReturnElement(X509qlParser.ReturnElementContext i) {
        QueryCert.Return x = new QueryCert.Return();
        x.variable = i.variableName().getText();
        if (i.fieldName != null) {
            x.fieldName = unquotes(i.fieldName.getText());
        }
        if (i.PATH() != null) {
            x.fieldName = "ξpath";
        }
        if (i.returnProp() != null) {
            if (i.returnProp().propName() != null) {
                x.prop = i.returnProp().propName().getText();
            } else {
                x.prop = "ξvalue";
            }
        }

        return x;
    }


    @Override
    public void enterFullColumnNameSelector(X509qlParser.FullColumnNameSelectorContext ctx) {
        QueryCert.Segments x = new QueryCert.Segments();
        ctx.selector().forEach(i -> x.selectors.add(addSelector(i)));
        if (ctx.REQUIRED() != null) {
            x.required = true;
        }
        qc.addSelect(x);
    }

    private QueryCert.Selector addSelector(X509qlParser.SelectorContext i) {
        if (i.star != null) {

        }

        QueryCert.Selector x = new QueryCert.Selector();

        if (i.ruid() != null) {
            x.expr = i.ruid().getText();
        }
        if (i.propfilter() != null) {
            x.props.addAll(mgetPropFilters(i.propfilter()));
        }
        if (i.valueFilter() != null) {
            x.value = getValueFilter(i.valueFilter());
        }
        if (i.variableAssignment() != null) {
            x.variable = i.variableAssignment().variableName().getText();
        }

        return x;
    }

    private QueryCert.ValueFilter getValueFilter(X509qlParser.ValueFilterContext valueFilter) {
        QueryCert.ValueFilter f = new QueryCert.ValueFilter();
        if (valueFilter.STRING_LITERAL() != null) {
            f.value = unquotes(valueFilter.STRING_LITERAL().getText());
        }
        f.props = mgetPropFilters(valueFilter.propfilter());
        return f;
    }

    private List<QueryCert.Prop> mgetPropFilters(X509qlParser.PropfilterContext propfilter) {
        final List<QueryCert.Prop> list = new ArrayList<>();
        if (propfilter != null) {
            propfilter.propmatcher().forEach(i -> list.add(getPropFilter(i)));
        }
        return list;
    }

    private QueryCert.Prop getPropFilter(X509qlParser.PropmatcherContext i) {
        QueryCert.Prop x = new QueryCert.Prop();
        x.prop = i.ruid().getText();
        x.value = i.STRING_LITERAL() == null ? "*" : unquotes(i.STRING_LITERAL().getText());
        return x;
    }

    private String unquotes(String text) {
        if (text == null)
            return null;
        return text.substring(1, text.length() - 1);
    }


    @Override
    public void enterSelectElements(X509qlParser.SelectElementsContext ctx) {


    }

    @Override
    public void exitSelectElements(X509qlParser.SelectElementsContext ctx) {

    }

    @Override
    public void enterSelectColumnElement(X509qlParser.SelectColumnElementContext ctx) {
    }

    @Override
    public void exitSelectColumnElement(X509qlParser.SelectColumnElementContext ctx) {

    }


    @Override
    public void enterReturnElement(X509qlParser.ReturnElementContext ctx) {

    }

    @Override
    public void exitReturnElement(X509qlParser.ReturnElementContext ctx) {

    }

    @Override
    public void enterReturnProp(X509qlParser.ReturnPropContext ctx) {

    }

    @Override
    public void exitReturnProp(X509qlParser.ReturnPropContext ctx) {

    }


    @Override
    public void enterPropName(X509qlParser.PropNameContext ctx) {

    }

    @Override
    public void exitPropName(X509qlParser.PropNameContext ctx) {

    }


    @Override
    public void enterVarid(X509qlParser.VaridContext ctx) {

    }

    @Override
    public void exitVarid(X509qlParser.VaridContext ctx) {

    }

    @Override
    public void enterRuid(X509qlParser.RuidContext ctx) {

    }

    @Override
    public void exitRuid(X509qlParser.RuidContext ctx) {

    }

    @Override
    public void enterVariableName(X509qlParser.VariableNameContext ctx) {

    }

    @Override
    public void exitVariableName(X509qlParser.VariableNameContext ctx) {

    }


    @Override
    public void enterSelectElementDepth(X509qlParser.SelectElementDepthContext ctx) {

    }

    @Override
    public void exitSelectElementDepth(X509qlParser.SelectElementDepthContext ctx) {

    }


    @Override
    public void enterIsExpression(X509qlParser.IsExpressionContext ctx) {

    }

    @Override
    public void exitIsExpression(X509qlParser.IsExpressionContext ctx) {

    }

    @Override
    public void enterNotExpression(X509qlParser.NotExpressionContext ctx) {

    }

    @Override
    public void exitNotExpression(X509qlParser.NotExpressionContext ctx) {

    }

    @Override
    public void enterLogicalExpression(X509qlParser.LogicalExpressionContext ctx) {

    }

    @Override
    public void exitLogicalExpression(X509qlParser.LogicalExpressionContext ctx) {

    }

    @Override
    public void enterPredicateExpression(X509qlParser.PredicateExpressionContext ctx) {

    }

    @Override
    public void exitPredicateExpression(X509qlParser.PredicateExpressionContext ctx) {

    }

    @Override
    public void enterLogicalOperator(X509qlParser.LogicalOperatorContext ctx) {

    }

    @Override
    public void exitLogicalOperator(X509qlParser.LogicalOperatorContext ctx) {

    }

    @Override
    public void enterExpressionAtomPredicate(X509qlParser.ExpressionAtomPredicateContext ctx) {

    }

    @Override
    public void exitExpressionAtomPredicate(X509qlParser.ExpressionAtomPredicateContext ctx) {

    }

    @Override
    public void enterBetweenPredicate(X509qlParser.BetweenPredicateContext ctx) {

    }

    @Override
    public void exitBetweenPredicate(X509qlParser.BetweenPredicateContext ctx) {

    }

    @Override
    public void enterBinaryComparasionPredicate(X509qlParser.BinaryComparasionPredicateContext ctx) {
    }

    @Override
    public void exitBinaryComparasionPredicate(X509qlParser.BinaryComparasionPredicateContext ctx) {
    }

    @Override
    public void enterIsNullPredicate(X509qlParser.IsNullPredicateContext ctx) {

    }

    @Override
    public void exitIsNullPredicate(X509qlParser.IsNullPredicateContext ctx) {

    }

    @Override
    public void enterLikePredicate(X509qlParser.LikePredicateContext ctx) {

    }

    @Override
    public void exitLikePredicate(X509qlParser.LikePredicateContext ctx) {

    }

    @Override
    public void enterRegexpPredicate(X509qlParser.RegexpPredicateContext ctx) {

    }

    @Override
    public void exitRegexpPredicate(X509qlParser.RegexpPredicateContext ctx) {

    }

    @Override
    public void enterComparisonOperator(X509qlParser.ComparisonOperatorContext ctx) {

    }

    @Override
    public void exitComparisonOperator(X509qlParser.ComparisonOperatorContext ctx) {

    }

    @Override
    public void enterNullNotnull(X509qlParser.NullNotnullContext ctx) {

    }

    @Override
    public void exitNullNotnull(X509qlParser.NullNotnullContext ctx) {

    }

    @Override
    public void enterUnaryExpressionAtom(X509qlParser.UnaryExpressionAtomContext ctx) {

    }

    @Override
    public void exitUnaryExpressionAtom(X509qlParser.UnaryExpressionAtomContext ctx) {

    }

    @Override
    public void enterConstantExpressionAtom(X509qlParser.ConstantExpressionAtomContext ctx) {

    }

    @Override
    public void exitConstantExpressionAtom(X509qlParser.ConstantExpressionAtomContext ctx) {

    }

    @Override
    public void enterFunctionCallExpressionAtom(X509qlParser.FunctionCallExpressionAtomContext ctx) {

    }

    @Override
    public void exitFunctionCallExpressionAtom(X509qlParser.FunctionCallExpressionAtomContext ctx) {

    }

    @Override
    public void enterBinaryExpressionAtom(X509qlParser.BinaryExpressionAtomContext ctx) {

    }

    @Override
    public void exitBinaryExpressionAtom(X509qlParser.BinaryExpressionAtomContext ctx) {

    }

    @Override
    public void enterFullColumnNameExpressionAtom(X509qlParser.FullColumnNameExpressionAtomContext ctx) {

    }

    @Override
    public void exitFullColumnNameExpressionAtom(X509qlParser.FullColumnNameExpressionAtomContext ctx) {

    }

    @Override
    public void enterBitExpressionAtom(X509qlParser.BitExpressionAtomContext ctx) {

    }

    @Override
    public void exitBitExpressionAtom(X509qlParser.BitExpressionAtomContext ctx) {

    }

    @Override
    public void enterNestedExpressionAtom(X509qlParser.NestedExpressionAtomContext ctx) {

    }

    @Override
    public void exitNestedExpressionAtom(X509qlParser.NestedExpressionAtomContext ctx) {

    }

    @Override
    public void enterMathExpressionAtom(X509qlParser.MathExpressionAtomContext ctx) {


    }

    @Override
    public void exitMathExpressionAtom(X509qlParser.MathExpressionAtomContext ctx) {

    }

    @Override
    public void enterUnaryOperator(X509qlParser.UnaryOperatorContext ctx) {

    }

    @Override
    public void exitUnaryOperator(X509qlParser.UnaryOperatorContext ctx) {

    }

    @Override
    public void enterBitOperator(X509qlParser.BitOperatorContext ctx) {

    }

    @Override
    public void exitBitOperator(X509qlParser.BitOperatorContext ctx) {

    }

    @Override
    public void enterMathOperator(X509qlParser.MathOperatorContext ctx) {

    }

    @Override
    public void exitMathOperator(X509qlParser.MathOperatorContext ctx) {

    }

    @Override
    public void enterConstant(X509qlParser.ConstantContext ctx) {

    }

    @Override
    public void exitConstant(X509qlParser.ConstantContext ctx) {

    }

    @Override
    public void enterBooleanLiteral(X509qlParser.BooleanLiteralContext ctx) {

    }

    @Override
    public void exitBooleanLiteral(X509qlParser.BooleanLiteralContext ctx) {

    }

    @Override
    public void enterDecimalLiteral(X509qlParser.DecimalLiteralContext ctx) {

    }

    @Override
    public void exitDecimalLiteral(X509qlParser.DecimalLiteralContext ctx) {

    }

    @Override
    public void enterFullId(X509qlParser.FullIdContext ctx) {

    }

    @Override
    public void exitFullId(X509qlParser.FullIdContext ctx) {

    }

    @Override
    public void enterFullColumnName(X509qlParser.FullColumnNameContext ctx) {

    }

    @Override
    public void exitFullColumnName(X509qlParser.FullColumnNameContext ctx) {

    }

    @Override
    public void exitFullColumnNameSelector(X509qlParser.FullColumnNameSelectorContext ctx) {

    }

    @Override
    public void enterVariableAssignment(X509qlParser.VariableAssignmentContext ctx) {

    }

    @Override
    public void exitVariableAssignment(X509qlParser.VariableAssignmentContext ctx) {

    }

    @Override
    public void enterSelector(X509qlParser.SelectorContext ctx) {

    }

    @Override
    public void exitSelector(X509qlParser.SelectorContext ctx) {

    }

    @Override
    public void enterValueFilter(X509qlParser.ValueFilterContext ctx) {

    }

    @Override
    public void exitValueFilter(X509qlParser.ValueFilterContext ctx) {

    }

    @Override
    public void enterPropfilter(X509qlParser.PropfilterContext ctx) {

    }

    @Override
    public void exitPropfilter(X509qlParser.PropfilterContext ctx) {

    }

    @Override
    public void enterPropmatcher(X509qlParser.PropmatcherContext ctx) {

    }

    @Override
    public void exitPropmatcher(X509qlParser.PropmatcherContext ctx) {

    }


    @Override
    public void enterPropsSelector(X509qlParser.PropsSelectorContext ctx) {

    }

    @Override
    public void exitPropsSelector(X509qlParser.PropsSelectorContext ctx) {
    }

    @Override
    public void enterPropSelector(X509qlParser.PropSelectorContext ctx) {
    }

    @Override
    public void exitPropSelector(X509qlParser.PropSelectorContext ctx) {

    }


    @Override
    public void enterUid(X509qlParser.UidContext ctx) {

    }

    @Override
    public void exitUid(X509qlParser.UidContext ctx) {

    }

    @Override
    public void enterSimpleId(X509qlParser.SimpleIdContext ctx) {

    }

    @Override
    public void exitSimpleId(X509qlParser.SimpleIdContext ctx) {

    }


    @Override
    public void enterUdfFunctionCall(X509qlParser.UdfFunctionCallContext ctx) {

    }

    @Override
    public void exitUdfFunctionCall(X509qlParser.UdfFunctionCallContext ctx) {

    }

    @Override
    public void enterFunctionArgs(X509qlParser.FunctionArgsContext ctx) {

    }

    @Override
    public void exitFunctionArgs(X509qlParser.FunctionArgsContext ctx) {

    }

    @Override
    public void visitTerminal(TerminalNode terminalNode) {

    }

    @Override
    public void visitErrorNode(ErrorNode errorNode) {
        throw new RuntimeException(errorNode.toString());
    }

    @Override
    public void enterEveryRule(ParserRuleContext parserRuleContext) {

    }

    @Override
    public void exitEveryRule(ParserRuleContext parserRuleContext) {

    }


    @Override
    public void enterRoot(X509qlParser.RootContext ctx) {

    }

    @Override
    public void exitRoot(X509qlParser.RootContext ctx) {

    }

    @Override
    public void enterSelectStatement(X509qlParser.SelectStatementContext ctx) {


    }

    @Override
    public void exitSelectStatement(X509qlParser.SelectStatementContext ctx) {

    }

    @Override
    public void enterReturnElements(X509qlParser.ReturnElementsContext ctx) {

    }

}
