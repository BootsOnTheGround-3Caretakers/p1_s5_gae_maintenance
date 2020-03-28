import io
from collections import OrderedDict

import flask


class Request(object):
    def arguments(self):
        return list(OrderedDict.fromkeys(flask.request.values.keys()))

    def get(self, key, default=None):
        return flask.request.values.get(key, default)

    @property
    def files(self):
        return flask.request.files


class Response(object):
    def __init__(self):
        self.headers = {}
        self.stream = io.BytesIO()
        self.status = None

    @property
    def out(self):
        return self

    def set_status(self, status):
        self.status = status

    def write(self, bytes_):
        if type(bytes_) != bytes:
            bytes_ = bytes_.encode('utf-8')

        self.stream.write(bytes_)


def wrap_webapp_class(handler_name):
    def flask_handler_wrapper(webapp_obj):
        def flask_handler(*args, **kwargs):
            webapp_obj.request = Request()
            webapp_obj.response = Response()
            getattr(webapp_obj, flask.request.method.lower())(*args, **kwargs)
            return flask.Response(
                webapp_obj.response.stream.getvalue(),
                status=webapp_obj.response.status, headers=webapp_obj.response.headers
            )

        # Flask requires each handler to have a unique name and it comes from the __name__ of the handler function
        flask_handler.__name__ = handler_name

        return flask_handler

    def class_wrapper(Cls):
        return flask_handler_wrapper(Cls())

    return class_wrapper
