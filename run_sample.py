import os
import sys
sys.path.append(os.path.dirname(__file__))
import rsproxy 

opt = {
    'listen-port': 5433,
    'server-port': 5432,
    'server-host': 'localhost',
}
dbsetting = { 
    'dbuser'     : 'dbuser',
    'dbpassword' : 'password',
    'users' : {
        'game13': {
            'password': '123',
            },
        }
}
rsproxy.setting.__dict__.update(dbsetting)
rsproxy.proxy.config.update(opt)
rsproxy.proxy.run()


