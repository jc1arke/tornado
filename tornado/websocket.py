#!/usr/bin/env python
#
# Copyright 2009 Bret Taylor
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import functools
import logging
import tornado.escape
import tornado.web
import struct
import hashlib
import re

class WebSocketHandler(tornado.web.RequestHandler):
    """A request handler for HTML 5 Web Sockets.

    See http://www.w3.org/TR/2009/WD-websockets-20091222/ for details on the
    JavaScript interface. We implement the protocol as specified at
    http://tools.ietf.org/html/draft-hixie-thewebsocketprotocol-55.

    Here is an example Web Socket handler that echos back all received messages
    back to the client:

      class EchoWebSocket(websocket.WebSocketHandler):
          def open(self):
              self.receive_message(self.on_message)

          def on_message(self, message):
             self.write_message(u"You said: " + message)

    Web Sockets are not standard HTTP connections. The "handshake" is HTTP,
    but after the handshake, the protocol is message-based. Consequently,
    most of the Tornado HTTP facilities are not available in handlers of this
    type. The only communication methods available to you are send_message()
    and receive_message(). Likewise, your request handler class should
    implement open() method rather than get() or post().

    If you map the handler above to "/websocket" in your application, you can
    invoke it in JavaScript with:

      var ws = new WebSocket("ws://localhost:8888/websocket");
      ws.onopen = function() {
         ws.send("Hello, world");
      };
      ws.onmessage = function (evt) {
         alert(evt.data);
      };

    This script pops up an alert box that says "You said: Hello, world".
    """
    def __init__(self, application, request):
        tornado.web.RequestHandler.__init__(self, application, request)
        self.stream = request.connection.stream

    def _execute(self, transforms, *args, **kwargs):
        if self.request.headers.get("Upgrade") != "WebSocket" or \
           self.request.headers.get("Connection") != "Upgrade" or \
           not self.request.headers.get("Origin"):
            message = "Expected WebSocket headers"
            self.stream.write(
                "HTTP/1.1 403 Forbidden\r\nContent-Length: " +
                str(len(message)) + "\r\n\r\n" + message)
            return
        
        if self.request.headers.get("Sec-WebSocket-Key1") and self.request.headers.get("Sec-WebSocket-Key2"):
            self._return_hixie76()
        else:
            self._return_hixie75() 
      
        self.async_callback(self.open)(*args, **kwargs)  
        
    
    def send_handshake(self, params):
    
        out = '''HTTP/1.1 101 Web Socket Protocol Handshake\r\nUpgrade: WebSocket\r\nConnection: Upgrade\r\nServer: TornadoServer/0.1\r\n'''
    
        response = {}
        #response["HTTP/1.1 101 Web Socket Protocol Handshake"] = ""
        #response["Upgrade"] = "WebSocket"
        #response["Connection"] = "Upgrade"
        #response["Server"] = "TornadoServer/0.1"
    
        if self.request.headers.get("Sec-WebSocket-Protocol"):
            # We should really validate if passed protocol is valid or not
            response["Sec-WebSocket-Protocol"] = self.request.headers.get("Sec-WebSocket-Protocol")
        
        response.update(params['headers'])    
        out += "\r\n".join(["%s: %s" % (header, response[header]) for header in response])
  
        if params.get('data') is not None:      
            out += "\r\n\r\n%s" % params['data']
        else:
            out += "\r\n\r\n"

        #out = "HTTP/1.1 101 Web Socket Protocol Handshake\r\n" + out
        self.stream.write(out)    



    def _return_hixie75(self):
        params = {}
        params['headers'] = {}
        params['headers']["WebSocket-Origin"] = self.request.headers["Origin"]
        params['headers']["WebSocket-Location"] = "ws://%s%s" % (self.request.host, self.request.path)
    
        self.send_handshake(params) 
    
    
    def _return_hixie76(self):        
        '''First part of the hixie76 return.
        The second bit lies in self._hixie76_challenge()'''
        self.stream.read_bytes(8, self._hixie76_challenge)
        
               
    
    def _hixie76_challenge(self, bit):
        '''Putting the hixie76 response together'''
        params = {}
        params['headers'] = {}
        params['headers']["Sec-WebSocket-Origin"] = self.request.headers["Origin"]
        params['headers']["Sec-WebSocket-Location"] = "ws://%s%s" % (self.request.host, self.request.path)
        
        key1 = self._get_key_value('Sec-Websocket-Key1')
        if key1 is None:
            raise Exception('Sec-WebSocket-Key1 not found')
        key2 = self._get_key_value('Sec-Websocket-Key2')
        if key2 is None:
            raise Exception('Sec-WebSocket-Key2 not found')
        # 5.2 8. let /challenge/ be the concatenation of /part_1/,
        challenge = ""
        challenge += struct.pack("!I", key1)  # network byteorder int
        challenge += struct.pack("!I", key2)  # network byteorder int
        challenge += bit # The trailing 8 bits of the challenge
        
        c = hashlib.md5()
        c.update(challenge)
        params['data'] = c.digest()

        self.send_handshake(params)
        
    
    def _get_key_value(self, key_field):
        '''Ripped from pywebsocket by Google.
        http://code.google.com/p/pywebsocket/source/browse/trunk/src/mod_pywebsocket/handshake/handshake.py
        With some customisations to make it fit in current context.'''
        key_value = self.request.headers.get(key_field)
        if key_value is None:
            logging.debug("no %s" % key_value)
            return None
        try:
            # 5.2 4. let /key-number_n/ be the digits (characters in the range
            # U+0030 DIGIT ZERO (0) to U+0039 DIGIT NINE (9)) in /key_n/,
            # interpreted as a base ten integer, ignoring all other characters
            # in /key_n/
            key_number = int(re.sub("\\D", "", key_value))
            # 5.2 5. let /spaces_n/ be the number of U+0020 SPACE characters
            # in /key_n/.
            spaces = re.subn(" ", "", key_value)[1]
            # 5.2 6. if /key-number_n/ is not an integral multiple of /spaces_n/
            # then abort the WebSocket connection.
            if key_number % spaces != 0:
                raise Exception('key_number %d is not an integral '
                                     'multiple of spaces %d' % (key_number,
                                                                spaces))
            # 5.2 7. let /part_n/ be /key_number_n/ divided by /spaces_n/.
            part = key_number / spaces
            logging.debug("%s: %s => %d / %d => %d" % (
                key_field, key_value, key_number, spaces, part))
            return part
        except:
            return None
                

    def write_message(self, message):
        """Sends the given message to the client of this Web Socket."""
        if isinstance(message, dict):
            message = tornado.escape.json_encode(message)
        if isinstance(message, unicode):
            message = message.encode("utf-8")
        assert isinstance(message, str)
        self.stream.write("\x00" + message + "\xff")

    def receive_message(self, callback):
        """Calls callback when the browser calls send() on this Web Socket."""
        callback = self.async_callback(callback)
        self.stream.read_bytes(
            1, functools.partial(self._on_frame_type, callback))

    def close(self):
        """Closes this Web Socket.

        The browser will receive the onclose event for the open web socket
        when this method is called.
        """
        self.stream.close()

    def async_callback(self, callback, *args, **kwargs):
        """Wrap callbacks with this if they are used on asynchronous requests.

        Catches exceptions properly and closes this Web Socket if an exception
        is uncaught.
        """
        if args or kwargs:
            callback = functools.partial(callback, *args, **kwargs)
        def wrapper(*args, **kwargs):
            try:
                return callback(*args, **kwargs)
            except Exception, e:
                logging.error("Uncaught exception in %s",
                              self.request.path, exc_info=True)
                self.stream.close()
        return wrapper

    def _on_frame_type(self, callback, byte):
        if ord(byte) & 0x80 == 0x80:
            raise Exception("Length-encoded format not yet supported")
        self.stream.read_until(
            "\xff", functools.partial(self._on_end_delimiter, callback))

    def _on_end_delimiter(self, callback, frame):
        callback(frame[:-1].decode("utf-8", "replace"))

    def _not_supported(self, *args, **kwargs):
        raise Exception("Method not supported for Web Sockets")

for method in ["write", "redirect", "set_header", "send_error", "set_cookie",
               "set_status", "flush", "finish"]:
    setattr(WebSocketHandler, method, WebSocketHandler._not_supported)
