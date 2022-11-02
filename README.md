# NATS Tools

> Tools to work with NATS server from Python.

## `NATSD`

Use this class to easily start/stop NATS servers:

```python
from nats_tools import NATSD


# Create a new nats-server daemon
natsd = NATSD(debug=True)

# Start the server
natsd.start()

# Stop the server
natsd.stop()
```

- Can be used as a context manager:

```python
with NATSD(debug=True) as natsd:
    print(natsd.proc.pid)
```

- Can be used to interact with monitoring API:

```python
with NATSD(debug=True) as natsd:
    # Show /varz endpoint
    print(natsd.monitor.varz())
    # Show /jsz endpoint
    print(natsd.monitor.jsz())
    # Show /connz endpoint
    print(natsd.monitor.connz)
```
