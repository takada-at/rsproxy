# coding: utf-8

import testconfig

from rsproxy import filters, parser

def test_createStartupMessage():
    msg = filters.createStartupMessage('dbuser', 'dbname')
    rawdata = msg.serialize()
    buff = parser.Buffer(rawdata)
    t = buff.get_char()
    assert ord(t)==0
    buff.get_char()
    leng = buff.get_int16()
    ver  = buff.get_int32()
    assert msg.type == 'Startup'
    assert leng == len(rawdata)
    assert ver  == 196608
    assert (ver >> 16)==3
    assert (ver & 0xffff)<2
    assert buff.remainder().split('\x00') == ['user', 'dbuser', 'database', 'dbname', '', '']


