# coding: utf-8

import testconfig
import sqlparse
from rsproxy import queryfilter

def test_filter_query_string():
    filterobj = queryfilter.QueryFilter(["app='game13'"],
                                        ['dau', 'sales_log'])

    # 必要な条件がある
    sql = "SELECT * from dau WHERE app='game13'"
    result0, = filterobj.filter_query_string(sql)
    assert result0[0]==True
    assert result0[1] is None

    # 必要な条件がある
    sql = "SELECT * from dau WHERE app='game13' AND date>='2013-07-01'"
    result1, = filterobj.filter_query_string(sql)
    assert result1[0]==True
    assert result1[1] is None

    # 必要な条件がない
    sql = "SELECT * from dau WHERE app='game05' AND date>='2013-07-01'"
    result2, = filterobj.filter_query_string(sql)
    assert result2[0]==False
    assert isinstance(result2[1], ValueError)

    # 必要な条件がない
    sql = "SELECT * from dau WHERE app='game05'"
    result3, = filterobj.filter_query_string(sql)
    assert result3[0]==False

    # 必要な条件がある
    sql = "SELECT * from dau WHERE app='game13' AND (state=1 OR state=2)"
    result4, = filterobj.filter_query_string(sql)
    assert result4[0]==True

    # UPDATE
    sql = "UPDATE dau SET value=1 WHERE app='game13' AND (state=1 OR state=2)"
    result5, = filterobj.filter_query_string(sql)
    assert result5[0]==True

    # テーブルが複数
    sql = "SELECT * from dau, sales_log WHERE app='game13' AND (state=1 OR state=2)"
    result6, = filterobj.filter_query_string(sql)
    assert result6[0]==False

    # テーブルが複数かつひとつはサブクエリ
    sql = "SELECT * from dau, (SELECT 1) WHERE app='game13' AND (state=1 OR state=2)"
    result7, = filterobj.filter_query_string(sql)
    assert result7[0]==False

    # テーブルなし
    sql = 'SELECT 1'
    result8, = filterobj.filter_query_string(sql)
    assert result8[0]==False

def test_get_table_name():
    sql = 'SELECT a,b,c FROM dau'
    statement, = sqlparse.parse(sql)
    result0 = queryfilter.get_table_name(statement)
    assert isinstance(result0, sqlparse.sql.Identifier)
    assert result0.value == 'dau'

    sql = 'SELECT * FROM dau, sales_log'
    statement, = sqlparse.parse(sql)
    result1 = queryfilter.get_table_name(statement)
    assert isinstance(result1, ValueError)

    sql = 'SELECT * FROM dau, (SELECT 1)'
    statement, = sqlparse.parse(sql)
    result2 = queryfilter.get_table_name(statement)
    assert isinstance(result2, ValueError)

    sql = 'SELECT * FROM dau LEFT JOIN sales'
    statement, = sqlparse.parse(sql)
    result3 = queryfilter.get_table_name(statement)
    assert isinstance(result3, ValueError)

    sql = 'SELECT * FROM dau WHERE app=1'
    statement, = sqlparse.parse(sql)
    result4 = queryfilter.get_table_name(statement)
    assert isinstance(result4, sqlparse.sql.Identifier)
    assert result4.value == 'dau'

    sql = 'SELECT * FROM (SELECT 1)'
    statement, = sqlparse.parse(sql)
    result5 = queryfilter.get_table_name(statement)
    assert isinstance(result5, ValueError)

    sql = 'SELECT 1+1'
    statement, = sqlparse.parse(sql)
    result6 = queryfilter.get_table_name(statement)
    assert isinstance(result6, ValueError)

    sql = 'SELECT * FROM dau AS d'
    statement, = sqlparse.parse(sql)
    result7 = queryfilter.get_table_name(statement)
    assert isinstance(result7, sqlparse.sql.Identifier)
    assert result7.value == 'dau'
