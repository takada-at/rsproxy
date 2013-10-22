import os
from twisted.internet import reactor
from twisted.application import service
from twisted.python import log
import sys
from server import PGProxyServerFactory
sys.path.append(os.path.dirname(__file__))

__all__ = ['__version__', 'proxy', 'application']


_this_dir = os.path.realpath(os.path.dirname(__file__))

__version__ = '0.0.1'


class RSProxy(service.Service):
    application = service.Application('rsproxy')

    def __init__(self):
        self.config = dict()
    def startService(self):
        log.startLogging(sys.stdout)
        self._port = reactor.listenTCP(self.config['listen-port'], PGProxyServerFactory(self))
        reactor.run()

    run = startService

proxy = RSProxy()
application = proxy.application
