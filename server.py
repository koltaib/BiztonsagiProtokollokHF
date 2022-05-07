import asyncio


class EchoServerProtocol(asyncio.Protocol):

    connections = { 'test_peername' : "somedata"}

    def connection_made(self, transport):
        peername = transport.get_extra_info('peername')
        print('Connection from {}'.format(peername))
        self.transport = transport

    def data_received(self, data):
        message = data.decode()
        print('Data received: {!r}'.format(message))
        reply = ""
        if(message == "pwd"):
            reply = "current working directory..."
        if(message == "lst"):
            reply = "List content of the current working directory..."
        if(message == "chd"):
            reply = "Change directory..."
        if(message == "mkd"):
            reply = "Make directory..."
        if(message == "del"):
            reply = "Delete file..."
        if(message == "upl"):
            reply = "Upload file..."
        if(message == "dnl"):
            reply = "Download file..."
        if(message == "Heló"):
            reply = "Hellóbelló..."
        if(message == "Viszlát"):
            reply = "A viszont látásra kedves Kliens."

        print('Send: {!r}'.format(reply))
        self.transport.write(reply.encode("utf_8"))

        host,port = self.transport.get_extra_info('peername')
        self.transport.write(host.encode("utf_8"))
        self.transport.write(str(port).encode("utf_8"))

        #print('Close the client socket')
        #self.transport.close()


async def main():
    # Get a reference to the event loop as we plan to use
    # low-level APIs.
    loop = asyncio.get_running_loop()

    server = await loop.create_server(
        lambda: EchoServerProtocol(),
        '127.0.0.1', 8888)

    async with server:
        await server.serve_forever()


asyncio.run(main())