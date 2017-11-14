# munt3r.py: a HTTP to STOMP-over-websocket shim for pentesters
 
## What does this do?
 
munt3r converts HTTP requests you send to its built in HTTP server into STOMP-over-websocket requests which are forwarded upstream, and then converts the websocket response back into HTTP on the return trip. 
 
## What's STOMP?
 
STOMP a protocol for pubsub and queue services like RabbitMQ, ActiveMQ etc. STOMP-over-websockets is exactly  what it says on the tin.  STOMP-over-websockets seems to be a fairly common way to implement a rich browser interface in the Spring world. STOMP requests typically look something like this:
 
    SEND
    destination:/app/xml.request
    content-length:288
    
    {"requestDetails":{"id":"11bcc574-49e9-4e58-82a0-b1b0a001b2a5","subId":"5148966c-80b7-4403-b643-28a45be63dcd"},"xmlMessage":"<request id=\"af5dc512-5b28-4739-9371-3d389c40f19c:666666\" method=\"getClientLinked\" service=\"CDS\"><clcode>666666</clcode><linkType>AUTO</linkType></request>"}
 
 
## What’s the point?
 
Testing websockets is kinda lame. The available tools just don't support websockets very well, if they do at all. All is not lost however, HTTP as a protocol is *extremely* well supported by a whole bunch of tools. munt3r lets you use your favourite HTTP compatible tools to test STOMP-over-websocket applications. For instance, you can now use Burp repeater, activescan or intruder, wfuzz or sqlmap or anything else you like
 
## How do I use this?
 
### Requirements
 
* python3
* pip -r requirements.txt
 
### Usage
 
    usage: munt3r.py [-h] [--port PORT] [--cookie COOKIE] [--host HOST]
                     [--subscribe SUB] [--verbose] URL. 
 
* URL is the URL used to upgrade to the websocket and must start with the "ws://" schema (i.e. "ws://example.com:8080/ws"). 
* --cookie is used to set an auth cookie, you should supply the full header value i.e. "JSESSIONID=xxxxxxx;Path=/;HttpOnly"
* --port is the port the web server will start on the loopback interface (default 9090)
* --host sets the Host and Origin headers
* --subscribe subscribes to a topic upon connection. You will generally need to subscribe to a topic to get any responses
* --verbose provides too much information
 
To use this to test, get the websocket URL and auth  cookie using burp. As STOMP is a pubsub protocol, you will probably need to subscribe to a topic to get responses to your request. Subscribe  requests start with SUBSCRIBE as a single word on the first line and generally happen immediately after a CONNECT request. The topic is in the "destination" header:
 
    SUBSCRIBE
    id:sub0
    destination:/user/queue/*
 
Note that websockets (and STOMP) is not a lock step tick-tock synchronous request/reply type protocol -- but munt3r will pretend that it is, and sometimes applications will use it that way. munt3r will always return the first reply after you send your request, whatever it is. This may or may not be appropriate. The following provides a typical example of command line arguments:
 
    python ./munt3r.py -v -p 9090 -H websocket-dev.local:65000 -s "/user/queue/*" -c "JSESSIONID=AC86749C01A1B5E1B0118A750717E61E;path=/;HttpOnly" ws://192.168.3.5:65000/ws
 
After the server starts up, you can now make HTTP POST requests to the local web server and have them turned into STOMP-over-websockets SEND requests. The HTTP URI path will be converted into the STOMP destination header. 
 
For example (burp proxy running 8080):
 
    curl  http://127.0.0.1:9090/app/alerts --proxy http://127.0.0.1:8080 -d '{"search":"hello"}'
 
Will be converted into the following STOMP request upstream:
 
    SEND
    destination:/app/alerts
    content-length:18
 
    {"search":"hello"}
 
After the request is captured in burp you can then use all of burps tools. To use sqlmap, build a POST request in a txt file with a custom injection mark (“*”) and launch it with the –r REQUESTFILE argument.
