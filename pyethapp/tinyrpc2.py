#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2013 Marc Brinkmann
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# This code has been copied from tinyrpc (https://github.com/mbr/tinyrpc),
# which is no longer actively maintained.

import inspect
import json
import six

import gevent.queue

from werkzeug.wrappers import Response, Request


class WsgiServerTransport(object):
    """WSGI transport.

    Requires :py:mod:`werkzeug`.

    Due to the nature of WSGI, this transport has a few pecularities: It must
    be run in a thread, greenlet or some other form of concurrent execution
    primitive.

    This is due to
    :py:func:`~tinyrpc.transports.wsgi.WsgiServerTransport.handle` blocking
    while waiting for a call to
    :py:func:`~tinyrpc.transports.wsgi.WsgiServerTransport.send_reply`.

    The parameter ``queue_class`` must be used to supply a proper queue class
    for the chosen concurrency mechanism (i.e. when using :py:mod:`gevent`,
    set it to :py:class:`gevent.queue.Queue`).

    :param max_content_length: The maximum request content size allowed. Should
                               be set to a sane value to prevent DoS-Attacks.
    :param queue_class: The Queue class to use.
    :param allow_origin: The ``Access-Control-Allow-Origin`` header. Defaults
                         to ``*`` (so change it if you need actual security).
    """
    def __init__(self, max_content_length=4096, queue_class=gevent.queue.Queue,
                       allow_origin='*'):
        self._queue_class = queue_class
        self.messages = queue_class()
        self.max_content_length = max_content_length
        self.allow_origin = allow_origin

    def receive_message(self):
        """Receive a message from the transport.

        Blocks until another message has been received. May return a context
        opaque to clients that should be passed on
        :py:func:`~tinyrpc.transport.Transport.send_reply` to identify the
        client later on.

        :return: A tuple consisting of ``(context, message)``.
        """
        return self.messages.get()

    def send_reply(self, context, reply):
        """Sends a reply to a client.

        The client is usually identified by passing ``context`` as returned
        from the original
        :py:func:`~tinyrpc.transport.Transport.receive_message` call.

        Messages must be strings, it is up to the sender to convert the
        beforehand. A non-string value raises a :py:exc:`TypeError`.

        :param context: A context returned by
                        :py:func:`~tinyrpc.transport.Transport.receive_message`.
        :param reply: A string to send back as the reply.
        """
        if not isinstance(reply, str):
            raise TypeError('str expected')

        context.put(reply)

    def handle(self, environ, start_response):
        """WSGI handler function.

        The transport will serve a request by reading the message and putting
        it into an internal buffer. It will then block until another
        concurrently running function sends a reply using
        :py:func:`~tinyrpc.transports.WsgiServerTransport.send_reply`.

        The reply will then be sent to the client being handled and handle will
        return.
        """
        request = Request(environ)
        request.max_content_length = self.max_content_length

        access_control_headers = {
            'Access-Control-Allow-Methods': 'POST',
            'Access-Control-Allow-Origin': self.allow_origin,
            'Access-Control-Allow-Headers': \
                'Content-Type, X-Requested-With, Accept, Origin'
        }

        if request.method == 'OPTIONS':
            response = Response(headers=access_control_headers)

        elif request.method == 'POST':
            # message is encoded in POST, read it...
            msg = request.stream.read()

            # create new context
            context = self._queue_class()

            self.messages.put((context, msg))

            # ...and send the reply
            response = Response(context.get(), headers=access_control_headers)
        else:
            # nothing else supported at the moment
            response = Response('Only POST supported', 405)

        return response(environ, start_response)


class RPCServerGreenlets(object):

    def __init__(self, transport, protocol, dispatcher):
        self.transport = transport
        self.protocol = protocol
        self.dispatcher = dispatcher

    def _spawn(self, func, *args, **kwargs):
        gevent.spawn(func, *args, **kwargs)

    def serve_forever(self):
        """Handle requests forever.

        Starts the server loop in which the transport will be polled for a new
        message.

        After a new message has arrived,
        :py:func:`~tinyrpc.server.RPCServer._spawn` is called with a handler
        function and arguments to handle the request.

        The handler function will try to decode the message using the supplied
        protocol, if that fails, an error response will be sent. After decoding
        the message, the dispatcher will be asked to handle the resultung
        request and the return value (either an error or a result) will be sent
        back to the client using the transport.

        After calling :py:func:`~tinyrpc.server.RPCServer._spawn`, the server
        will fetch the next message and repeat.
        """
        while True:
            self.receive_one_message()

    def receive_one_message(self):
        context, message = self.transport.receive_message()

        # assuming protocol is threadsafe and dispatcher is theadsafe, as
        # long as its immutable

        def handle_message(context, message):
            try:
                request = self.protocol.parse_request(message)
            except RPCError as e:
                response = e.error_respond()
            else:
                response = self.dispatcher.dispatch(request)

            # send reply
            self.transport.send_reply(context, response.serialize())

        self._spawn(handle_message, context, message)


class RPCDispatcher(object):
    """Stores name-to-method mappings."""

    def __init__(self):
        self.method_map = {}
        self.subdispatchers = {}

    def add_subdispatch(self, dispatcher, prefix=''):
        """Adds a subdispatcher, possibly in its own namespace.

        :param dispatcher: The dispatcher to add as a subdispatcher.
        :param prefix: A prefix. All of the new subdispatchers methods will be
                       available as prefix + their original name.
        """
        self.subdispatchers.setdefault(prefix, []).append(dispatcher)

    def add_method(self, f, name=None):
        """Add a method to the dispatcher.

        :param f: Callable to be added.
        :param name: Name to register it with. If ``None``, ``f.__name__`` will
                     be used.
        """
        assert callable(f), "method argument must be callable"
                            # catches a few programming errors that are
                            # commonly silently swallowed otherwise
        if not name:
            name = f.__name__

        if name in self.method_map:
            raise RPCError('Name %s already registered')

        self.method_map[name] = f

    def dispatch(self, request):
        """Fully handle request.

        The dispatch method determines which method to call, calls it and
        returns a response containing a result.

        No exceptions will be thrown, rather, every exception will be turned
        into a response using :py:func:`~tinyrpc.RPCRequest.error_respond`.

        If a method isn't found, a :py:exc:`~tinyrpc.exc.MethodNotFoundError`
        response will be returned. If any error occurs outside of the requested
        method, a :py:exc:`~tinyrpc.exc.ServerError` without any error
        information will be returend.

        If the method is found and called but throws an exception, the
        exception thrown is used as a response instead. This is the only case
        in which information from the exception is possibly propagated back to
        the client, as the exception is part of the requested method.

        :py:class:`~tinyrpc.RPCBatchRequest` instances are handled by handling
        all its children in order and collecting the results, then returning an
        :py:class:`~tinyrpc.RPCBatchResponse` with the results.

        :param request: An :py:func:`~tinyrpc.RPCRequest`.
        :return: An :py:func:`~tinyrpc.RPCResponse`.
        """
        if hasattr(request, 'create_batch_response'):
            results = [self._dispatch(req) for req in request]

            response = request.create_batch_response()
            if response != None:
                response.extend(results)

            return response
        else:
            return self._dispatch(request)

    def _dispatch(self, request):
        try:
            try:
                method = self.get_method(request.method)
            except KeyError as e:
                return request.error_respond(MethodNotFoundError(e))

            # we found the method
            try:
                result = method(*request.args, **request.kwargs)
            except Exception as e:
                # an error occured within the method, return it
                return request.error_respond(e)

            # respond with result
            return request.respond(result)
        except Exception as e:
            # unexpected error, do not let client know what happened
            return request.error_respond(ServerError())

    def get_method(self, name):
        """Retrieve a previously registered method.

        Checks if a method matching ``name`` has been registered.

        If :py:func:`get_method` cannot find a method, every subdispatcher
        with a prefix matching the method name is checked as well.

        If a method isn't found, a :py:class:`KeyError` is thrown.

        :param name: Callable to find.
        :param return: The callable.
        """
        if name in self.method_map:
            return self.method_map[name]

        for prefix, subdispatchers in six.iteritems(self.subdispatchers):
            if name.startswith(prefix):
                for sd in subdispatchers:
                    try:
                        return sd.get_method(name[len(prefix):])
                    except KeyError:
                        pass

        raise KeyError(name)

    def public(self, name=None):
        """Convenient decorator.

        Allows easy registering of functions to this dispatcher. Example:

        .. code-block:: python

            dispatch = RPCDispatcher()

            @dispatch.public
            def foo(bar):
                # ...

            class Baz(object):
                def not_exposed(self):
                    # ...

                @dispatch.public(name='do_something')
                def visible_method(arg1)
                    # ...

        :param name: Name to register callable with
        """
        if callable(name):
            self.add_method(name)
            return name

        def _(f):
            self.add_method(f, name=name)
            return f

        return _

    def register_instance(self, obj, prefix=''):
        """Create new subdispatcher and register all public object methods on
        it.

        To be used in conjunction with the :py:func:`tinyrpc.dispatch.public`
        decorator (*not* :py:func:`tinyrpc.dispatch.RPCDispatcher.public`).

        :param obj: The object whose public methods should be made available.
        :param prefix: A prefix for the new subdispatcher.
        """
        dispatch = self.__class__()
        for name, f in inspect.getmembers(
            obj, lambda f: callable(f) and hasattr(f, '_rpc_public_name')
        ):
            dispatch.add_method(f, f._rpc_public_name)

        # add to dispatchers
        self.add_subdispatch(dispatch, prefix)


class JSONRPCProtocol(object):
    """JSONRPC protocol implementation.

    Currently, only version 2.0 is supported."""

    JSON_RPC_VERSION = "2.0"
    _ALLOWED_REPLY_KEYS = sorted(['id', 'jsonrpc', 'error', 'result'])
    _ALLOWED_REQUEST_KEYS = sorted(['id', 'jsonrpc', 'method', 'params'])

    def __init__(self, *args, **kwargs):
        super(JSONRPCProtocol, self).__init__(*args, **kwargs)
        self._id_counter = 0

    def _get_unique_id(self):
        self._id_counter += 1
        return self._id_counter

    def create_batch_request(self, requests=None):
        return JSONRPCBatchRequest(requests or [])

    def create_request(self, method, args=None, kwargs=None, one_way=False):
        """Creates a new RPCRequest object.

        It is up to the implementing protocol whether or not ``args``,
        ``kwargs``, one of these, both at once or none of them are supported.

        :param method: The method name to invoke.
        :param args: The positional arguments to call the method with.
        :param kwargs: The keyword arguments to call the method with.
        :param one_way: The request is an update, i.e. it does not expect a
                        reply.
        :return: A new :py:class:`~tinyrpc.RPCRequest` instance.
        """
        if args and kwargs:
            raise InvalidRequestError('Does not support args and kwargs at '\
                                      'the same time')

        request = JSONRPCRequest()

        if not one_way:
            request.unique_id = self._get_unique_id()

        request.method = method
        request.args = args
        request.kwargs = kwargs

        return request

    def parse_reply(self, data):
        """Parses a reply and returns an :py:class:`RPCResponse` instance.

        :return: An instanced response.
        """
        if six.PY3 and isinstance(data, bytes):
            # zmq won't accept unicode strings, and this is the other
            # end; decoding non-unicode strings back into unicode
            data = data.decode()

        try:
            rep = json.loads(data)
        except Exception as e:
            raise InvalidReplyError(e)

        for k in six.iterkeys(rep):
            if not k in self._ALLOWED_REPLY_KEYS:
                raise InvalidReplyError('Key not allowed: %s' % k)

        if not 'jsonrpc' in rep:
            raise InvalidReplyError('Missing jsonrpc (version) in response.')

        if rep['jsonrpc'] != self.JSON_RPC_VERSION:
            raise InvalidReplyError('Wrong JSONRPC version')

        if not 'id' in rep:
            raise InvalidReplyError('Missing id in response')

        if ('error' in rep) == ('result' in rep):
            raise InvalidReplyError(
                'Reply must contain exactly one of result and error.'
            )

        if 'error' in rep:
            response = JSONRPCErrorResponse()
            error = rep['error']
            response.error = error['message']
            response._jsonrpc_error_code = error['code']
        else:
            response = JSONRPCSuccessResponse()
            response.result = rep.get('result', None)

        response.unique_id = rep['id']

        return response

    def parse_request(self, data):
        """Parses a request given as a string and returns an
        :py:class:`RPCRequest` instance.

        :return: An instanced request.
        """
        if six.PY3 and isinstance(data, bytes):
            # zmq won't accept unicode strings, and this is the other
            # end; decoding non-unicode strings back into unicode
            data = data.decode()

        try:
            req = json.loads(data)
        except Exception as e:
            raise JSONRPCParseError()

        if isinstance(req, list):
            # batch request
            requests = JSONRPCBatchRequest()
            for subreq in req:
                try:
                    requests.append(self._parse_subrequest(subreq))
                except RPCError as e:
                    requests.append(e)
                except Exception as e:
                    requests.append(JSONRPCInvalidRequestError())

            if not requests:
                raise JSONRPCInvalidRequestError()
            return requests
        else:
            return self._parse_subrequest(req)

    def _parse_subrequest(self, req):
        for k in six.iterkeys(req):
            if not k in self._ALLOWED_REQUEST_KEYS:
                raise JSONRPCInvalidRequestError()

        if req.get('jsonrpc', None) != self.JSON_RPC_VERSION:
            raise JSONRPCInvalidRequestError()

        if not isinstance(req['method'], six.string_types):
            raise JSONRPCInvalidRequestError()

        request = JSONRPCRequest()
        request.method = str(req['method'])
        request.unique_id = req.get('id', None)

        params = req.get('params', None)
        if params != None:
            if isinstance(params, list):
                request.args = req['params']
            elif isinstance(params, dict):
                request.kwargs = req['params']
            else:
                raise JSONRPCInvalidParamsError()

        return request


class JSONRPCRequest(object):
    unique_id = None
    """A unique ID to remember the request by. Protocol specific, may or
    may not be set. This value should only be set by
    :py:func:`~tinyrpc.RPCProtocol.create_request`.

    The ID allows client to receive responses out-of-order and still allocate
    them to the correct request.

    Only supported if the parent protocol has
    :py:attr:`~tinyrpc.RPCProtocol.supports_out_of_order` set to ``True``.
    """

    method = None
    """The name of the method to be called."""

    args = []
    """The positional arguments of the method call."""

    kwargs = {}
    """The keyword arguments of the method call."""

    def error_respond(self, error):
        """Creates an error response.

        Create a response indicating that the request was parsed correctly,
        but an error has occured trying to fulfill it.

        :param error: An exception or a string describing the error.

        :return: A response or ``None`` to indicate that no error should be sent
                 out.
        """
        if self.unique_id is None:
            return None

        response = JSONRPCErrorResponse()

        code, msg = _get_code_and_message(error)

        response.error = msg
        response.unique_id = self.unique_id
        response._jsonrpc_error_code = code
        return response

    def respond(self, result):
        """Create a response.

        Call this to return the result of a successful method invocation.

        This creates and returns an instance of a protocol-specific subclass of
        :py:class:`~tinyrpc.RPCResponse`.

        :param result: Passed on to new response instance.

        :return: A response or ``None`` to indicate this request does not expect a
                 response.
        """
        response = JSONRPCSuccessResponse()

        if self.unique_id is None:
            return None

        response.result = result
        response.unique_id = self.unique_id

        return response

    def _to_dict(self):
        jdata = {
            'jsonrpc': JSONRPCProtocol.JSON_RPC_VERSION,
            'method': self.method,
        }
        if self.args:
            jdata['params'] = self.args
        if self.kwargs:
            jdata['params'] = self.kwargs
        if self.unique_id != None:
            jdata['id'] = self.unique_id
        return jdata

    def serialize(self):
        """Returns a serialization of the request.

        :return: A string to be passed on to a transport.
        """
        return json.dumps(self._to_dict())


class JSONRPCBatchRequest(list):
    """Multiple requests batched together.

    A batch request is a subclass of :py:class:`list`. Protocols that support
    multiple requests in a single message use this to group them together.

    Handling a batch requests is done in any order, responses must be gathered
    in a batch response and be in the same order as their respective requests.

    Any item of a batch request is either a request or a subclass of
    :py:class:`~tinyrpc.BadRequestError`, which indicates that there has been
    an error in parsing the request.
    """

    def create_batch_response(self):
        """Creates a response suitable for responding to this request.

        :return: An :py:class:`~tinyrpc.RPCBatchResponse` or ``None``, if no
                 response is expected."""
        if self._expects_response():
            return JSONRPCBatchResponse()

    def _expects_response(self):
        for request in self:
            if isinstance(request, Exception):
                return True
            if request.unique_id != None:
                return True

        return False

    def serialize(self):
        return json.dumps([req._to_dict() for req in self])


class RPCResponse(object):
    """RPC call response class.

    Base class for all deriving responses.

    Has an attribute ``result`` containing the result of the RPC call, unless
    an error occured, in which case an attribute ``error`` will contain the
    error message."""

    unique_id = None

    def serialize(self):
        """Returns a serialization of the response.

        :return: A reply to be passed on to a transport.
        """
        raise NotImplementedError()


class JSONRPCSuccessResponse(RPCResponse):
    def _to_dict(self):
        return {
            'jsonrpc': JSONRPCProtocol.JSON_RPC_VERSION,
            'id': self.unique_id,
            'result': self.result,
        }

    def serialize(self):
        return json.dumps(self._to_dict())


class JSONRPCErrorResponse(RPCResponse):
    def _to_dict(self):
        return {
            'jsonrpc': JSONRPCProtocol.JSON_RPC_VERSION,
            'id': self.unique_id,
            'error': {
                'message': str(self.error),
                'code': self._jsonrpc_error_code,
            }
        }

    def serialize(self):
        return json.dumps(self._to_dict())


class JSONRPCBatchResponse(list):
    """Multiple response from a batch request. See
    :py:class:`~tinyrpc.RPCBatchRequest` on how to handle.

    Items in a batch response need to be
    :py:class:`~tinyrpc.RPCResponse` instances or None, meaning no reply should
    generated for the request.
    """

    def serialize(self):
        """Returns a serialization of the batch response."""
        return json.dumps([resp._to_dict() for resp in self if resp != None])


class RPCError(Exception):
    """Base class for all excetions thrown by :py:mod:`tinyrpc`."""


class ServerError(RPCError):
    """An internal error in the RPC system occured."""


class MethodNotFoundError(RPCError):
    """The desired method was not found."""


class BadRequestError(RPCError):
    """Base class for all errors that caused the processing of a request to
    abort before a request object could be instantiated."""

    def error_respond(self):
        """Create :py:class:`~tinyrpc.RPCErrorResponse` to respond the error.

        :return: A error responce instance or ``None``, if the protocol decides
                 to drop the error silently."""
        raise RuntimeError('Not implemented')


class InvalidRequestError(BadRequestError):
    """A request made was malformed (i.e. violated the specification) and could
    not be parsed."""


class FixedErrorMessageMixin(object):
    def __init__(self, *args, **kwargs):
        if not args:
            args = [self.message]
        super(FixedErrorMessageMixin, self).__init__(*args, **kwargs)

    def error_respond(self):
        response = JSONRPCErrorResponse()

        response.error = self.message
        response.unique_id = None
        response._jsonrpc_error_code = self.jsonrpc_error_code
        return response


class JSONRPCInvalidParamsError(FixedErrorMessageMixin, InvalidRequestError):
    jsonrpc_error_code = -32602
    message = 'Invalid params'


class JSONRPCInvalidRequestError(FixedErrorMessageMixin, InvalidRequestError):
    jsonrpc_error_code = -32600
    message = 'Invalid Request'


class JSONRPCParseError(FixedErrorMessageMixin, InvalidRequestError):
    jsonrpc_error_code = -32700
    message = 'Parse error'


class JSONRPCMethodNotFoundError(FixedErrorMessageMixin, MethodNotFoundError):
    jsonrpc_error_code = -32601
    message = 'Method not found'


class JSONRPCServerError(FixedErrorMessageMixin, InvalidRequestError):
    jsonrpc_error_code = -32000
    message = ''


class BadReplyError(RPCError):
    """Base class for all errors that caused processing of a reply to abort
    before it could be turned in a response object."""


class InvalidReplyError(BadReplyError):
    """A reply received was malformed (i.e. violated the specification) and
    could not be parsed into a response."""


def _get_code_and_message(error):
    assert isinstance(error, (Exception, six.string_types))
    if isinstance(error, Exception):
        if hasattr(error, 'jsonrpc_error_code'):
            code = error.jsonrpc_error_code
            msg = str(error)
        elif isinstance(error, InvalidRequestError):
            code = JSONRPCInvalidRequestError.jsonrpc_error_code
            msg = JSONRPCInvalidRequestError.message
        elif isinstance(error, MethodNotFoundError):
            code = JSONRPCMethodNotFoundError.jsonrpc_error_code
            msg = JSONRPCMethodNotFoundError.message
        else:
            # allow exception message to propagate
            code = JSONRPCServerError.jsonrpc_error_code
            msg = str(error)
    else:
        code = -32000
        msg = error

    return code, msg


def public_(name=None):
    """Set RPC name on function.

    This function decorator will set the ``_rpc_public_name`` attribute on a
    function, causing it to be picked up if an instance of its parent class is
    registered using
    :py:func:`~tinyrpc.dispatch.RPCDispatcher.register_instance`.

    ``@public`` is a shortcut for ``@public()``.

    :param name: The name to register the function with.
    """
    # called directly with function
    if callable(name):
        f = name
        f._rpc_public_name = f.__name__
        return f

    def _(f):
        f._rpc_public_name = name or f.__name__
        return f

    return _
