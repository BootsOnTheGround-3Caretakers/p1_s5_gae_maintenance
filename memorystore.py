import six

if six.PY2:
    from google.appengine.api import memcache
else:
    import redis

from secret import get_redis_host, get_redis_port


class Client(object):
    def __init__(self):
        if six.PY2:
            self.wrapped_client = memcache.Client()
        else:
            self.wrapped_client = redis.StrictRedis(
                host=get_redis_host(), port=int(get_redis_port()), password=None
            )

    def get(self, name):
        return self.wrapped_client.get(name)

    def set(self, name, value):
        return self.wrapped_client.set(name, value)
