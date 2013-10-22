# coding:utf-8

import sqlparse
from sqlparse.sql import Where, Identifier, IdentifierList, Token, Parenthesis
from sqlparse.tokens import Keyword, Punctuation

class QueryFilter(object):
    #u"""
    # Usage:
    # filterobj = QueryFilter(["app='game13'"], ['sometable'])
    # result, exceptionobj = filterobj.filter_query_string(string)
    #
    # →SELECT文でないか、またはSELECT文であり、app='game13'という条件が入っており、sometableに対するクエリ以外はresultがFalseになる
    #"""
    def __init__(self, expected_conditions, tables=None):
        if expected_conditions:
            self.expected_conditions = set(expected_conditions)
        else:
            self.expected_conditions = None

        if tables:
            self.tables = set(tables)
        else:
            self.tables = None

    def filter_query_string(self, string):
        return filter_query_string(string, self.expected_conditions, self.tables)

def filter_query_string(string, expected_conditions, tables):
    parsed_statements = sqlparse.parse(string)
    return [filter_statement(stmt, expected_conditions, tables) for stmt in parsed_statements]

def filter_statement(statement, expected_conditions, tables):
    u"""
    * SELECT以外→OK
    * WHERE節がない→はじく
    * テーブルが複数、テーブルがない、FROM中のサブクエリ→はじく
    * 単一テーブルだが、対象テーブルではない → はじく
    * WHERE節を最上位のANDで区切る。条件の中に期待される条件を含むわけではない→はじく
    * 条件の中に期待される条件を含む→OK
    """
    statement_type = get_statement_type(statement)
    if statement_type!='SELECT':
        return (True, ValueError('statement type: %s' % statement_type))

    where_clause = get_where_clause(statement)
    if where_clause is None:
        return (False, ValueError('no where clause'))

    target_table = get_table_name(statement)
    if isinstance(target_table, ValueError):
        return (False, target_table)
    else:
        tablename = target_table.value
        if tablename not in tables:
            return (False, ValueError('invalid table name: %s' % tablename))

    select_expr_check = check_select_expr(statement)
    if isinstance(select_expr_check, ValueError):
        return (False, select_expr_check)

    tokens = [token for token in where_clause.tokens if not token.is_whitespace()]
    conditions = split_tokens(tokens[1:], 'AND')
    condition_strs = set()
    for condition in conditions:
        condition_str = "".join([token.value for token in condition])
        condition_strs.add(condition_str)

    if (expected_conditions - condition_strs)==set([]):
        return (True, None)
    else:
        return (False, ValueError('invalid conditions'))

def get_statement_type(statement):
    return statement.get_type()

def check_select_expr(statement):
    tokens = [token for token in statement.tokens if not token.is_whitespace()]
    splitted   = split_tokens(tokens, 'FROM')
    tokens     = splitted[0][1:]
    for token in tokens:
        if isinstance(token, Parenthesis):
            return ValueError('invalid select expr')

    return tokens

def get_table_name(statement):
    tokens = [token for token in statement.tokens if not token.is_whitespace()]
    state = 0
    tablename = None
    splitted   = split_tokens(tokens, 'FROM')
    if len(splitted)==1:
        #FROMなし
        return ValueError('no table')

    target = splitted[1][0]
    if len(splitted[1])>1:
        nextkeyword = splitted[1][1]
    else:
        nextkeyword = None

    if isinstance(target, Identifier):
        if nextkeyword and nextkeyword.ttype==Punctuation:
            return ValueError('multipule tables')
        elif nextkeyword and nextkeyword.ttype==Keyword:
            # おそらくJOIN
            return ValueError('multiple tables')

        return target
    elif isinstance(target, IdentifierList):
        return ValueError('multiple tables')
    elif isinstance(target, Parenthesis):
        return ValueError('subquery')
    else:
        # ??
        return ValueError('invalid table')

def get_where_clause(statement):
    for child in statement.get_sublists():
        if isinstance(child, Where):
            return child

    return None

def split_tokens(tokens, value, tokentype=Keyword):
    res = []
    sub = []
    for token in tokens:
        if token.value.upper() == value and token.ttype==tokentype:
            res.append(sub)
            sub = []
        else:
            sub.append(token)

    if sub: res.append(sub)
    return res
