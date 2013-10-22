# coding:utf-8
import base64
import hashlib
import hmac
import struct

from twisted.internet import reactor
from twisted.python import log

import inspect
import parser
import queryfilter
import setting

class UserAuth(object):
    def __init__(self, user):
        self.user = user
        self.authenticationComplete = False
    def auth(self, password, authmsg):
        expected_password = setting.users[self.user]['password']
        salt = authmsg.buffer.raw_value()[-4:]
        pw   = crypt_md5(salt, expected_password, self.user)
        result = password == pw
        if result:
            log.msg('auth ok')
            self.authenticationComplete = True

        return result

def createZMessage(status='E'):
    text = 'Z' + struct.pack("!I", 5) + status
    m = parser.BackendParser()
    m.consume(text)
    return m

def createErrorMessage(message, path, line, funcname):
    head = 'E'
    params = ['S''FATAL', 'C''28000', 
              'M'+message,
              'F'+path,
              'L'+str(line), 
              'R'+funcname, '']
    body = '\x00'.join(params) + '\x00'
    size = struct.pack("!I", len(body)+4)
    text = 'E' + size + body
    m = parser.BackendParser()
    m.consume(text)
    return m

def createStartupMessage(user, database):
    params = ['user', user, 'database', database, '']
    body   =  '\x00'.join(params) + '\x00'
    head   = struct.pack("!II", len(body) + 8, 196608)
    binary = head + body
    m = parser.FrontendParser()
    m.consume(binary)
    return m

def crypt_md5(salt, text, user):
    m  = hashlib.md5()
    m.update(text + user)
    pw = m.hexdigest()
    m  = hashlib.md5()
    m.update(pw + salt)
    pw = 'md5' + m.hexdigest()
    return pw

def createPasswordMessage(password, dbuser, response):
    authmsg = response[0]
    if authmsg.status == 5:
        salt = authmsg.buffer.raw_value()[-4:]
        string = crypt_md5(salt, password, dbuser)
        length = len(string) + 4
        binary = 'p' + struct.pack("!I", length) + string
        m = parser.FrontendParser()
        m.consume(binary)
        return m

class Filter(object):
    """
    Base class for filters. By default, messages are not altered. To implement
    a derived filter, create methods named filter_<message type code> (so for 
    example, filter_Q would be called when a frontend query message passed 
    through the filter). 

    Each filter function should return one of: 

        self.transmit(msg)        - Just pass the message on to the peer. 
        self.drop(msg)            - Do not pass the message on to the peer. 
        self.translate(*messages) - In place of msg, return one or more messages
                                    in its place. 

    The filter can also call self.spoof(messages) to send replies back to its
    protocol. These replies are deferred. 

    Each protocol (which corresponds to one socket) has one filter associated 
    with it. The protocol using the filter is available via the self.protocol
    field. 
    """
    def __init__(self, protocol):
        self.protocol = protocol
        self.dropMessages = ''


    def ignoreMessages(self, messageTypes):
        """
        Given a string in which the characters are the sequence of
        message types to ignore, causes the filter to drop the
        messages as they are received in that order, without
        additional processing. 
        """
        self.dropMessages += messageTypes


    def filter(self, msg):
        """
        Filters the message. Returns a message or a set of messages to 
        be written to the peer.
        """
        if msg.type == self.dropMessages[:1]:
            self.dropMessages = self.dropMessages[1:]
            return self.drop(msg, 'instructed to ignore')
        return getattr(self, 'filter_' + msg.type, self.transmit)(msg)


    def transmit(self, msg):
        """
        Returns the message without changing it. 
        """
        return [msg], None


    def translate(self, *messages):
        """
        Converts the message to one or more different messages. 
        """
        return messages, None


    def drop(self, msg, why=''):
        """
        Returns a value that will result in the current message being dropped.
        """
        l = 'Dropping message: %s' % msg
        if why:
            l += ' because: %s' % why
        log.msg(l)
        return None, None


    def spoof(self, messages):
        """
        Sends the provided list of messages back to the protocol's transport. 
        """
        log.msg('Spoofing data: %s' % ''.join(map(str, messages)))
        data = ''.join([m.serialize() for m in messages])
        reactor.callLater(0, lambda: self.protocol.transport.write(data))

class FrontendFilter(Filter):
    """
    Filters the messages coming from the client to the PG server. This
    also handles pgproxy custom syntax: BEGIN TEST, ROLLBACK TEST,
    etc.

    Queries are inspected here, mostly to detect transaction-related 
    operations. There are various match_* functions defined to divide
    this work into manageable pieces. 
    
    """
    # Cache some stock replies for messages that we'll be dropping or 
    # translating. 
    def __init__(self, protocol):
        Filter.__init__(self, protocol)

    def filter_Startup(self, msg):
        """
        スタートアップコマンド。
        """
        params = msg.parseDict()
        self.userAuth = UserAuth(params['user'])
        pg = self.protocol.postgresProtocol

        #クエリフィルターの作成
        cond = "app='%s'" % params['user']
        self.queryfilter = queryfilter.QueryFilter([cond], ['dau', 'sales_log', 'sales_person', 'person_app_data', 'logintime'])
        #バックエンドの認証が終わっていれば、バックエンドには何も送らない
        if pg.authenticationComplete:
            self.spoof(pg.authenticationResponse[0:1])
            return self.drop(msg)

        #バックエンドの認証開始
        nmsg = createStartupMessage(setting.dbuser,
                                    params['database'])

        return self.transmit(nmsg)

    def filter_SSLRequest(self, msg):
        #SSLモードは無しにする
        m = parser.BackendParser()
        m.consume('N\x00')
        self.spoof([m])
        return self.drop(msg)

    def filter_p(self, msg):
        u"""
        PasswordMessage
        """
        pg = self.protocol.postgresProtocol
        if self.userAuth:
            password = msg.password
            authmsg = pg.authenticationResponse[0]
            # frontend user authentication
            if not self.userAuth.auth(password, authmsg):
                # Frontend認証失敗。エラーメッセージを返して切断
                user = self.userAuth.user
                errorMsg = createErrorMessage('password authentication failed for user "%s"' % user,
                                              __file__,
                                              inspect.currentframe().f_lineno,
                                              'filter_p'
                                              )
                self.spoof([errorMsg])
                return self.drop(msg)
            else:
                # Frontend認証成功。認証メッセージをすべて送る
                self.spoof(pg.authenticationResponse[1:])

        return self.drop(msg)

    def _ignoreBackendMessages(self, messageTypes):
        """
        Tells the backend to ignore the given set of message replies. 
        """
        self.postgresProtocol().ignoreMessages(messageTypes)


    def postgresProtocol(self):
        """
        Returns the postgres protocol peered with the owner protocol of 
        this filter. 
        """
        return self.protocol.getPeer()


    def filter_X(self, msg):
        """
        Drops terminate messages.
        """
        return self.drop(msg)

    def filter_P(self, msg):
        u"""
        プリペアドステートメントは許可しない
        """
        user = self.userAuth.user
        zMsg     = createZMessage()
        errorMsg = createErrorMessage('query authentication failed for user "%s"' % user,
                                      __file__,
                                      inspect.currentframe().f_lineno,
                                      'filter_P'
                                      )
        self.spoof([zMsg, errorMsg])
        return self.drop(msg)

    def filter_Q(self, msg):
        u"""
        SQLのフィルタリング
        """
        query = msg.data[:-1]
        result, = self.queryfilter.filter_query_string(query)
        if result[0]:
            return self.transmit(msg)
        else:
            user = self.userAuth.user
            zMsg     = createZMessage()
            errorMsg = createErrorMessage('query authentication failed for user "%s"' % user,
                                          __file__,
                                          inspect.currentframe().f_lineno,
                                          'filter_Q'
                                          )
            self.spoof([zMsg, errorMsg])
            return self.drop(msg)

class BackendFilter(Filter):
    """
    Filters the messages coming from the PG server to the client. 
    """    
    def saveAuth(self, msg):
        """
        Saves authentication response messages from the backend. These will be
        sent to new frontends without actually re-authenticating. 
        """
        self.protocol.saveAuthMessage(msg)
        return self.transmit(msg)

    def filter_R(self, msg):
        # バックエンドの認証を行なう部分
        # AuthenticationMD5Passwordにのみ対応
        if msg.status==5:
            pg = self.protocol
            nmsg = createPasswordMessage(setting.dbpassword, setting.dbuser, [msg])
            log.msg('send %s' % nmsg)
            self.spoof([nmsg])

        return self.saveAuth(msg)

    filter_S = saveAuth
    filter_K = saveAuth

    def filter_Z(self, msg):
        """
        ReadyForQuery。認証終了
        """
        self.protocol.setTransactionStatus(msg.transaction_status)
        if not self.protocol.authenticationComplete:
            self.protocol.saveAuthMessage(msg)
        return self.transmit(msg)

