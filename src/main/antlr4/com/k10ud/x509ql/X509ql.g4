grammar X509ql;

// mvn clean org.antlr:antlr4-maven-plugin:antlr4

@parser::members
{

  @Override
  public void notifyErrorListeners(Token offendingToken, String msg, RecognitionException ex)
  {
    throw new RuntimeException(msg);
  }
}

@lexer::members
{
  @Override
  public void recover(RecognitionException ex)
  {
    throw new RuntimeException(ex.getMessage());
  }
}



SELECT:                              'SELECT';
SET:                              'SET';
OPTIONAL:                              'OPTIONAL';
MATCH:                              'MATCH';
RETURN:                              'RETURN';
WHERE:                              'WHERE';
AS:                              'AS';
NOT:                              'NOT';
IS:                              'IS';
TRUE:                              'TRUE';
FALSE:                              'FALSE';
UNKNOWN:                              'UNKNOWN';
AND:                              'AND';
XOR:                              'XOR';
OR:                              'OR';
BETWEEN:                              'BETWEEN';
REGEXP:                              'REGEXP';
RLIKE:                              'RLIKE';
LIKE:                              'LIKE';
ESCAPE:                              'ESCAPE';
BINARY:                              'BINARY';
DIV:                              'DIV';
MOD:                              'MOD';
DEPTH:                              'DEPTH';
PATH:                              'PATH';
REQUIRED: 'REQUIRED';


REVERSE_QUOTE_ID:                    '`' ~'`'+ '`';
NULL_LITERAL:                        'NULL';
NULL_SPEC_LITERAL:                   '\\' 'N';
STRING_LITERAL:                      DQUOTA_STRING | SQUOTA_STRING | BQUOTA_STRING;
fragment DQUOTA_STRING:              '"' ( '\\'. | '""' | ~('"'| '\\') )* '"';
fragment SQUOTA_STRING:              '\'' ('\\'. | '\'\'' | ~('\'' | '\\'))* '\'';
fragment BQUOTA_STRING:              '`' ( '\\'. | '``' | ~('`'|'\\'))* '`';
fragment HEX_DIGIT:                  [0-9A-F];
fragment DEC_DIGIT:                  [0-9];
fragment BIT_STRING_L:               'B' '\'' [01]+ '\'';
DECIMAL_LITERAL:                     DEC_DIGIT+;
ZERO_DECIMAL:                        '0';
ONE_DECIMAL:                         '1';
TWO_DECIMAL:                         '2';
HEXADECIMAL_LITERAL:                 [xX] '\'' (HEX_DIGIT HEX_DIGIT)+ '\''
                                     | '0' [xX] HEX_DIGIT+;
REAL_LITERAL:                        (DEC_DIGIT+)? '.' DEC_DIGIT+
                                           | DEC_DIGIT+ '.' EXPONENT_NUM_PART
                                           | (DEC_DIGIT+)? '.' (DEC_DIGIT+ EXPONENT_NUM_PART)
                                           | DEC_DIGIT+ EXPONENT_NUM_PART;
BIT_STRING:                          BIT_STRING_L;
fragment EXPONENT_NUM_PART:          'E' [-+]? DEC_DIGIT+;



fragment ID_LITERAL:                 [A-Za-z_0-9.]+[A-Za-z_0-9.]*;
ID:                 ID_LITERAL;

fragment RID_LITERAL:                 [A-Za-z_0-9.*]+[A-Za-z_0-9.*]*;
RID:                 RID_LITERAL;


root
    : selectStatement EOF
    ;

selectStatement
    : (MATCH selectElements)? (WHERE whereExpr=expression)? (RETURN returnElements)?
    ;


returnElements
    : ( returnElement ) (',' returnElement)*
    ;


selectElements
    : ( selectElement ) (',' selectElement)*
    ;

selectElement
    : fullColumnNameSelector  propsSelector?   #selectColumnElement
    ;


propsSelector
    : '{'  propSelector (',' propSelector)*  '}'
    ;

propSelector
    : simpleId
    ;

returnElement
    :  variableName returnProp? ('AS' (fieldName=STRING_LITERAL|PATH))?
    ;

returnProp
    :  '{' propName? '}'
    ;

/*
returnElement
    :  returnItem ('AS' fieldName=STRING_LITERAL)?
    ;

returnItem
    :   functionName=funcName '(' returnItem (',' returnItem)*  ')' #functionExpression
      | variableName ('{' propName '}')?               #variableExpression
      | constant                                       #constantExpression
    ;


*/

variableName
    : varid
    ;

selectElementDepth
    : DEPTH (ALL|decimalLiteral)?
    ;


// Simplified approach for expression
expression
    : notOperator=(NOT | '!') expression                            #notExpression
    | expression logicalOperator expression                         #logicalExpression
    | predicate IS NOT? testValue=(TRUE | FALSE | UNKNOWN)          #isExpression
    | predicate                                                     #predicateExpression
    ;

logicalOperator
    : AND | '&' '&' | XOR | OR | '|' '|'
    ;

predicate
    : predicate IS nullNotnull                                      #isNullPredicate
    | left=predicate comparisonOperator right=predicate             #binaryComparasionPredicate
    | predicate NOT? BETWEEN predicate AND predicate                #betweenPredicate
    | predicate NOT? LIKE predicate (ESCAPE STRING_LITERAL)?        #likePredicate
    | predicate NOT? regex=(REGEXP | RLIKE) predicate               #regexpPredicate
    | expressionAtom                                                #expressionAtomPredicate
    ;

comparisonOperator
    : '=' | '>' | '<' | '<' '=' | '>' '='
    | '<' '>' | '!' '=' | '<' '=' '>'
    ;


nullNotnull
    : NOT? (NULL_LITERAL | NULL_SPEC_LITERAL)
    ;

// Add in ASTVisitor nullNotnull in constant
expressionAtom
    : constant                                                      #constantExpressionAtom
    | fullColumnName                                                #fullColumnNameExpressionAtom
    | functionCall                                                  #functionCallExpressionAtom
    | unaryOperator expressionAtom                                  #unaryExpressionAtom
    | BINARY expressionAtom                                         #binaryExpressionAtom
    | '(' expression (',' expression)* ')'                          #nestedExpressionAtom
    | left=expressionAtom bitOperator right=expressionAtom          #bitExpressionAtom
    | left=expressionAtom mathOperator right=expressionAtom         #mathExpressionAtom
    ;

unaryOperator
    : '!' | '~' | '+' | '-' | NOT
    ;

bitOperator
    : '<' '<' | '>' '>' | '&' | '^' | '|'
    ;




constant
    : STRING_LITERAL | decimalLiteral
    | '-' decimalLiteral
    | HEXADECIMAL_LITERAL | booleanLiteral
    | REAL_LITERAL | BIT_STRING
    | NOT? nullLiteral=(NULL_LITERAL | NULL_SPEC_LITERAL)
    ;



booleanLiteral
    : TRUE | FALSE;

decimalLiteral
    : DECIMAL_LITERAL | ZERO_DECIMAL | ONE_DECIMAL | TWO_DECIMAL
    ;



fullId
    : uid ('/' uid)*
    ;

fullColumnName
    : uid ('/' uid)*
    ;


fullColumnNameSelector
    :  REQUIRED?  '/'?selector ('/'selector)*
    ;

variableAssignment
    : variableName ':='
    ;

selector
    :  variableAssignment? (star='*'| ruid)? propfilter? valueFilter?
    ;

valueFilter
    : '=' STRING_LITERAL? propfilter?
    ;


propfilter
    : '{'  propmatcher (',' propmatcher)*  '}'
    ;

propmatcher
    :  ruid ( ':' STRING_LITERAL)?
    ;



uid
    : simpleId
    | REVERSE_QUOTE_ID
    ;

simpleId
    : varid
    ;





functionCall
    : fullId '(' functionArgs? ')'                                  #udfFunctionCall
    ;

functionArgs
    : (constant | fullColumnName | functionCall | expression)
    (
      ','
      (constant | fullColumnName | functionCall | expression)
    )*
    ;

WS: [ \t\r\n]+ -> skip;




mathOperator
    : '*' | '/' | '%' | DIV | MOD | '+' | '-' | '--'
    ;



propName:                 ID;


varid:                 '$'ID;

ruid:                 ID|RID;




