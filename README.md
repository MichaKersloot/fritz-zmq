# Fritz!Box ZMQ Flow Capture Tool

This tool creates a high-performance bridge between an AVM Fritz!Box and ntopng. It streams raw network packets from the Fritz!Box's internal capture interface, performs Deep Packet Inspection (DPI) to identify IPv4 flows, and publishes them over ZeroMQ (ZMQ) in a format natively understood by ntopng.

## Prerequisites

* A Fritz!Box with at least FRITZ!OS 6.x.
* A dedicated user on the Fritz!Box with administrator permissions (required for capture access).
* Docker and Docker Compose installed on your host.

## Quick Start

1. **Clone the repository** and place capture.cpp, Dockerfile, and docker-compose.yml in the same directory.
2. **Configure credentials**: Edit docker-compose.yml and set your Fritz!Box IP, username, and password.
3. **Launch the stack**:
   `docker-compose up -d --build`
4. **Access ntopng**: Open http://your-host-ip:3000 in your browser. The Fritz!Box interface will appear as zmq://fritz-zmq:5556.

## Configuration Parameters

| Environment Variable | Default | Description |
| :--- | :--- | :--- |
| FRITZBOX_IP | 192.168.178.1 | IP address of your Fritz!Box |
| FRITZBOX_USERNAME | admin | Fritz!Box username |
| FRITZBOX_PASSWORD | | Fritz!Box password |
| FRITZBOX_INTERFACE | 3-0 | The interface to capture (3-0 is typically WAN/DSL) |
| DEBUG_FLOWS | false | Set to true to print flow details to console logs |

## Monitoring

Check the container logs for heartbeats and status:

`docker logs -f fritz-zmq`

Every 5 seconds, the tool prints a [HEARTBEAT] showing the total number of flows successfully processed and sent.

## Important Note on Performance

**Packet capture is a CPU-intensive task for the Fritz!Box.** On high-speed internet connections or older router models, enabling this tool may lead to:
* Reduced maximum network throughput.
* Increased latency (ping).
* High CPU load on the Fritz!Box.

It is recommended to monitor your router's performance when first enabling this tool.

## License

MIT License.