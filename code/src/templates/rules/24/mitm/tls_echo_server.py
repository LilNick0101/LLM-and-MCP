#!/usr/bin/env python3
#!/usr/bin/env python3
import asyncio
import ssl

# >>> Replace with your host LAN IP <<<
LISTEN_HOST = "192.168.1.50"
LISTEN_PORT = 443

CERT_FILE = 'fake_cert.pem'
KEY_FILE = 'fake_key.pem'


async def handle_client(reader, writer):
    peer = writer.get_extra_info("peername")
    print(f"[+] Connection from {peer}")

    try:
        # Read TLS ClientHello (or HTTP bytes)
        data = await reader.read(4096)

        if not data:
            print(f"[!] Empty connection from {peer}")
            return

        print(f"[+] Received {len(data)} bytes from {peer}")
        print(f"    Raw (first 32 bytes): {data[:32].hex()}")

        # Add your code here
        
        await writer.drain()

    except Exception as e:
        print(f"[!] Error with {peer}: {e}")

    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except:
            pass

        print(f"[+] Connection with {peer} closed")


async def main():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT_FILE, KEY_FILE)

    server = await asyncio.start_server(
        handle_client, LISTEN_HOST, LISTEN_PORT, ssl=ctx
    )

    print(f"[+] TLS echo server listening on {LISTEN_HOST}:{LISTEN_PORT}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())