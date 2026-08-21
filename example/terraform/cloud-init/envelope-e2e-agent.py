#!/usr/bin/env python3
"""Small bounded TCP/UDP workload agent for Envelope E2E probes."""

from __future__ import annotations

import argparse
import json
import queue
import re
import socket
import sys
import threading
import time
from collections.abc import Callable, Sequence
from typing import Any, Literal, cast


ProtocolName = Literal["tcp", "udp"]

MAX_FRAME_BYTES = 4096
MAX_MESSAGES = 100_000
MAX_TIMEOUT_SECONDS = 21_600.0
MAX_TCP_CLIENTS = 32
_TCP_ACCEPT_POLL_SECONDS = 0.1
_TCP_SHUTDOWN_SECONDS = 2.0
_FLOW_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")


class AgentError(RuntimeError):
    pass


def _protocol(value: str) -> ProtocolName:
    if value not in ("tcp", "udp"):
        raise AgentError("protocol must be tcp or udp")
    return cast(ProtocolName, value)


def _flow_id(value: str, field: str = "flow_id") -> str:
    if not _FLOW_ID_RE.fullmatch(value):
        raise AgentError(f"{field} must be a 1-128 character identifier")
    return value


def _port(value: int, field: str, *, allow_zero: bool = False) -> int:
    minimum = 0 if allow_zero else 1
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= 65_535:
        raise AgentError(f"{field} must be between {minimum} and 65535")
    return value


def _timeout(value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value <= MAX_TIMEOUT_SECONDS:
        raise AgentError(f"timeout must be greater than zero and at most {MAX_TIMEOUT_SECONDS:g} seconds")
    return value


def _message_count(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_MESSAGES:
        raise AgentError(f"message count must be between 1 and {MAX_MESSAGES}")
    return value


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise AgentError("operation timed out")
    return remaining


def _set_timeout(sock: socket.socket, deadline: float) -> None:
    sock.settimeout(_remaining(deadline))


def _marker(flow_id: str, connection_id: str, sequence: int, kind: str) -> dict[str, Any]:
    return {
        "connection_id": connection_id,
        "flow_id": flow_id,
        "kind": kind,
        "sequence": sequence,
    }


def _encode_frame(value: dict[str, Any], *, newline: bool) -> bytes:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    if newline:
        encoded += b"\n"
    if len(encoded) > MAX_FRAME_BYTES:
        raise AgentError("protocol frame exceeds the size bound")
    return encoded


def _decode_frame(data: bytes, *, expected_kinds: set[str]) -> dict[str, Any]:
    if not data or len(data) > MAX_FRAME_BYTES:
        raise AgentError("protocol frame is empty or oversized")
    try:
        value = json.loads(data.decode("ascii").strip())
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AgentError("protocol frame is not ASCII JSON") from error
    if not isinstance(value, dict) or set(value) != {"connection_id", "flow_id", "kind", "sequence"}:
        raise AgentError("protocol frame has the wrong shape")
    flow_id = value["flow_id"]
    connection_id = value["connection_id"]
    sequence = value["sequence"]
    kind = value["kind"]
    if not isinstance(flow_id, str) or not isinstance(connection_id, str):
        raise AgentError("protocol frame identifiers must be strings")
    _flow_id(flow_id)
    _flow_id(connection_id, "connection_id")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
        raise AgentError("protocol frame sequence must be a non-negative integer")
    if kind not in expected_kinds:
        raise AgentError("protocol frame kind is invalid")
    return cast(dict[str, Any], value)


class _FrameReader:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buffer = bytearray()

    def receive(self, deadline: float) -> bytes:
        while True:
            newline = self.buffer.find(b"\n")
            if newline >= 0:
                frame = bytes(self.buffer[:newline])
                del self.buffer[: newline + 1]
                return frame
            if len(self.buffer) >= MAX_FRAME_BYTES:
                raise AgentError("TCP protocol frame exceeds the size bound")
            _set_timeout(self.sock, deadline)
            try:
                chunk = self.sock.recv(min(1024, MAX_FRAME_BYTES + 1 - len(self.buffer)))
            except socket.timeout as error:
                raise AgentError("operation timed out") from error
            if not chunk:
                if self.buffer:
                    raise AgentError("TCP protocol frame ended without a delimiter")
                raise EOFError
            self.buffer.extend(chunk)


def _send_tcp(sock: socket.socket, value: dict[str, Any], deadline: float) -> None:
    _set_timeout(sock, deadline)
    try:
        sock.sendall(_encode_frame(value, newline=True))
    except socket.timeout as error:
        raise AgentError("operation timed out") from error


def _send_udp(sock: socket.socket, value: dict[str, Any], deadline: float) -> None:
    _set_timeout(sock, deadline)
    try:
        sent = sock.send(_encode_frame(value, newline=False))
    except socket.timeout as error:
        raise AgentError("operation timed out") from error
    if sent <= 0:
        raise AgentError("UDP protocol frame was not sent")


def _receive_udp(sock: socket.socket, deadline: float) -> bytes:
    _set_timeout(sock, deadline)
    try:
        data = sock.recv(MAX_FRAME_BYTES + 1)
    except socket.timeout as error:
        raise AgentError("operation timed out") from error
    if len(data) > MAX_FRAME_BYTES:
        raise AgentError("UDP protocol frame exceeds the size bound")
    return data


def _client_socket(
    protocol: ProtocolName,
    host: str,
    port: int,
    source_ip: str,
    source_port: int,
    deadline: float,
) -> socket.socket:
    sock_type = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
    sock = socket.socket(socket.AF_INET, sock_type)
    try:
        sock.bind((source_ip, source_port))
        _set_timeout(sock, deadline)
        sock.connect((host, port))
    except (OSError, socket.timeout):
        sock.close()
        raise
    return sock


def _validate_ack(ack: dict[str, Any], flow_id: str, connection_id: str, sequence: int) -> None:
    if (
        ack["kind"] != "ack"
        or ack["flow_id"] != flow_id
        or ack["connection_id"] != connection_id
        or ack["sequence"] != sequence
    ):
        raise AgentError("response does not acknowledge the requested flow marker")


def probe(
    protocol: str,
    host: str,
    port: int,
    *,
    source_ip: str,
    source_port: int,
    flow_id: str,
    timeout: float,
) -> dict[str, Any]:
    selected_protocol = _protocol(protocol)
    _port(port, "port")
    _port(source_port, "source_port", allow_zero=True)
    _flow_id(flow_id)
    deadline = time.monotonic() + _timeout(timeout)
    connection_id = _flow_id(f"{flow_id}:c0001", "connection_id")
    try:
        sock = _client_socket(selected_protocol, host, port, source_ip, source_port, deadline)
        with sock:
            started_ns = time.monotonic_ns()
            request = _marker(flow_id, connection_id, 0, "probe")
            if selected_protocol == "tcp":
                reader = _FrameReader(sock)
                _send_tcp(sock, request, deadline)
                ack = _decode_frame(reader.receive(deadline), expected_kinds={"ack"})
            else:
                _send_udp(sock, request, deadline)
                ack = _decode_frame(_receive_udp(sock, deadline), expected_kinds={"ack"})
            received_ns = time.monotonic_ns()
            _validate_ack(ack, flow_id, connection_id, 0)
            local_ip, local_port = sock.getsockname()[:2]
    except AgentError:
        raise
    except (OSError, socket.timeout) as error:
        raise AgentError(f"probe socket operation failed: {type(error).__name__}") from None
    return {
        "connection_id": connection_id,
        "flow_id": flow_id,
        "latency_ns": received_ns - started_ns,
        "local_ip": local_ip,
        "operation": "probe",
        "protocol": selected_protocol,
        "sequence": 0,
        "source_port": local_port,
        "success": True,
    }


def stream(
    protocol: str,
    host: str,
    port: int,
    *,
    source_ip: str,
    source_port: int,
    flow_id: str,
    count: int,
    interval: float,
    timeout: float,
) -> dict[str, Any]:
    selected_protocol = _protocol(protocol)
    _port(port, "port")
    _port(source_port, "source_port", allow_zero=True)
    _flow_id(flow_id)
    _message_count(count)
    if isinstance(interval, bool) or not isinstance(interval, (int, float)) or interval < 0 or interval > 60:
        raise AgentError("stream interval must be between 0 and 60 seconds")
    deadline = time.monotonic() + _timeout(timeout)
    connection_id = _flow_id(f"{flow_id}:c0001", "connection_id")
    markers: list[dict[str, Any]] = []
    try:
        sock = _client_socket(selected_protocol, host, port, source_ip, source_port, deadline)
        with sock:
            reader = _FrameReader(sock) if selected_protocol == "tcp" else None
            local_ip, local_port = sock.getsockname()[:2]
            next_send = time.monotonic()
            for sequence in range(count):
                delay = next_send - time.monotonic()
                if delay > 0:
                    if delay >= _remaining(deadline):
                        raise AgentError("operation timed out")
                    time.sleep(delay)
                sent_ns = time.monotonic_ns()
                request = _marker(flow_id, connection_id, sequence, "marker")
                if selected_protocol == "tcp":
                    assert reader is not None
                    _send_tcp(sock, request, deadline)
                    ack = _decode_frame(reader.receive(deadline), expected_kinds={"ack"})
                else:
                    _send_udp(sock, request, deadline)
                    ack = _decode_frame(_receive_udp(sock, deadline), expected_kinds={"ack"})
                received_ns = time.monotonic_ns()
                _validate_ack(ack, flow_id, connection_id, sequence)
                markers.append(
                    {
                        "connection_id": connection_id,
                        "flow_id": flow_id,
                        "received_monotonic_ns": received_ns,
                        "sent_monotonic_ns": sent_ns,
                        "sequence": sequence,
                    }
                )
                next_send = max(next_send + interval, time.monotonic())
    except AgentError:
        raise
    except (OSError, socket.timeout) as error:
        raise AgentError(f"stream socket operation failed: {type(error).__name__}") from None
    return {
        "connection_id": connection_id,
        "flow_id": flow_id,
        "local_ip": local_ip,
        "markers": markers,
        "operation": "stream",
        "protocol": selected_protocol,
        "socket_count": 1,
        "source_port": local_port,
        "success": True,
    }


class _TCPServeState:
    def __init__(self, max_messages: int):
        self.condition = threading.Condition()
        self.max_messages = max_messages
        self.reserved_messages = 0
        self.messages = 0
        self.connections = 0
        self.flow_ids: set[str] = set()
        self.error: AgentError | None = None
        self.stopping = False

    def start_connection(self) -> int | None:
        with self.condition:
            if self.stopping:
                return None
            self.connections += 1
            return self.connections

    def reserve_message(self) -> bool:
        with self.condition:
            if self.stopping or self.reserved_messages >= self.max_messages:
                return False
            self.reserved_messages += 1
            return True

    def complete_message(self, flow_id: str) -> None:
        with self.condition:
            self.messages += 1
            self.flow_ids.add(flow_id)
            if self.messages == self.max_messages:
                self.stopping = True
            self.condition.notify_all()

    def fail(self, error: AgentError) -> None:
        with self.condition:
            if not self.stopping and self.error is None:
                self.error = error
                self.stopping = True
            self.condition.notify_all()

    def stop(self) -> None:
        with self.condition:
            self.stopping = True
            self.condition.notify_all()

    def status(self) -> tuple[int, int, set[str], AgentError | None, bool]:
        with self.condition:
            return self.messages, self.connections, set(self.flow_ids), self.error, self.stopping

    def wait(self, timeout: float) -> None:
        with self.condition:
            self.condition.wait(timeout)

    def notify(self) -> None:
        with self.condition:
            self.condition.notify_all()


def _serve_tcp_connection(
    connection: socket.socket,
    deadline: float,
    state: _TCPServeState,
) -> None:
    try:
        with connection:
            reader = _FrameReader(connection)
            connection_id: str | None = None
            while True:
                try:
                    data = reader.receive(deadline)
                except EOFError:
                    return
                request = _decode_frame(data, expected_kinds={"probe", "marker"})
                if connection_id is None:
                    connection_id = request["connection_id"]
                elif request["connection_id"] != connection_id:
                    raise AgentError("one TCP socket changed connection_id")
                if not state.reserve_message():
                    return
                ack = _marker(request["flow_id"], request["connection_id"], request["sequence"], "ack")
                _send_tcp(connection, ack, deadline)
                state.complete_message(request["flow_id"])
    except AgentError as error:
        state.fail(error)
    except OSError as error:
        state.fail(AgentError(f"TCP server socket operation failed: {type(error).__name__}"))
    except Exception as error:
        state.fail(AgentError(f"TCP server worker failed: {type(error).__name__}"))
    finally:
        state.notify()


def _serve_tcp(
    listener: socket.socket,
    deadline: float,
    max_messages: int,
) -> tuple[int, int, set[str]]:
    state = _TCPServeState(max_messages)
    workers: dict[threading.Thread, socket.socket] = {}
    cleanup_error: AgentError | None = None
    try:
        while True:
            for worker in [thread for thread in workers if not thread.is_alive()]:
                worker.join()
                workers.pop(worker).close()

            messages, _connections, _flow_ids, error, stopping = state.status()
            if error is not None or messages == max_messages:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                state.fail(AgentError("operation timed out"))
                break
            if stopping:
                break
            if len(workers) >= MAX_TCP_CLIENTS:
                state.wait(min(_TCP_ACCEPT_POLL_SECONDS, remaining))
                continue

            listener.settimeout(min(_TCP_ACCEPT_POLL_SECONDS, remaining))
            try:
                connection, _peer = listener.accept()
            except socket.timeout:
                continue
            except OSError as error:
                state.fail(AgentError(f"TCP server accept failed: {type(error).__name__}"))
                break

            connection_number = state.start_connection()
            if connection_number is None:
                connection.close()
                break
            worker = threading.Thread(
                target=_serve_tcp_connection,
                args=(connection, deadline, state),
                name=f"envelope-e2e-tcp-{connection_number:05d}",
                daemon=True,
            )
            workers[worker] = connection
            try:
                worker.start()
            except RuntimeError as error:
                workers.pop(worker).close()
                state.fail(AgentError(f"TCP server worker start failed: {type(error).__name__}"))
                break
    finally:
        listener.close()
        state.stop()
        for connection in workers.values():
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        shutdown_deadline = time.monotonic() + _TCP_SHUTDOWN_SECONDS
        for worker in workers:
            worker.join(max(0.0, shutdown_deadline - time.monotonic()))
        if any(worker.is_alive() for worker in workers):
            cleanup_error = AgentError("TCP server workers did not stop cleanly")

    messages, connections, flow_ids, error, _stopping = state.status()
    if error is not None:
        raise error
    if cleanup_error is not None:
        raise cleanup_error
    if messages != max_messages:
        raise AgentError("TCP server stopped before the global message bound")
    return messages, connections, flow_ids


def _serve_udp(
    listener: socket.socket,
    deadline: float,
    max_messages: int,
) -> tuple[int, int, set[str]]:
    messages = 0
    peers: set[tuple[str, int, str]] = set()
    flow_ids: set[str] = set()
    while messages < max_messages:
        _set_timeout(listener, deadline)
        try:
            data, peer = listener.recvfrom(MAX_FRAME_BYTES + 1)
        except socket.timeout as error:
            raise AgentError("operation timed out") from error
        if len(data) > MAX_FRAME_BYTES:
            raise AgentError("UDP protocol frame exceeds the size bound")
        request = _decode_frame(data, expected_kinds={"probe", "marker"})
        flow_ids.add(request["flow_id"])
        peers.add((str(peer[0]), int(peer[1]), request["connection_id"]))
        ack = _marker(request["flow_id"], request["connection_id"], request["sequence"], "ack")
        _set_timeout(listener, deadline)
        try:
            listener.sendto(_encode_frame(ack, newline=False), peer)
        except socket.timeout as error:
            raise AgentError("operation timed out") from error
        messages += 1
    return messages, len(peers), flow_ids


def serve(
    protocol: str,
    bind_ip: str,
    port: int,
    *,
    timeout: float,
    max_messages: int,
    ready: Callable[[int], None] | None = None,
) -> dict[str, Any]:
    selected_protocol = _protocol(protocol)
    _port(port, "port", allow_zero=True)
    _message_count(max_messages)
    deadline = time.monotonic() + _timeout(timeout)
    sock_type = socket.SOCK_STREAM if selected_protocol == "tcp" else socket.SOCK_DGRAM
    try:
        with socket.socket(socket.AF_INET, sock_type) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((bind_ip, port))
            actual_port = int(listener.getsockname()[1])
            if selected_protocol == "tcp":
                listener.listen(MAX_TCP_CLIENTS)
            if ready is not None:
                ready(actual_port)
            if selected_protocol == "tcp":
                messages, connections, flow_ids = _serve_tcp(listener, deadline, max_messages)
            else:
                messages, connections, flow_ids = _serve_udp(listener, deadline, max_messages)
    except AgentError:
        raise
    except OSError as error:
        raise AgentError(f"serve socket operation failed: {type(error).__name__}") from None
    return {
        "bind_ip": bind_ip,
        "connections": connections,
        "flow_ids": sorted(flow_ids),
        "messages": messages,
        "operation": "serve",
        "port": actual_port,
        "protocol": selected_protocol,
        "success": True,
    }


def self_test() -> dict[str, Any]:
    if _timeout(MAX_TIMEOUT_SECONDS) != MAX_TIMEOUT_SECONDS:
        raise AgentError("timeout boundary self-test failed")
    try:
        _timeout(MAX_TIMEOUT_SECONDS + 1.0)
    except AgentError:
        pass
    else:
        raise AgentError("timeout overflow self-test failed")

    client_count = 4
    messages_per_client = 2
    ready: queue.Queue[int] = queue.Queue(maxsize=1)
    server_results: list[dict[str, Any]] = []
    server_errors: list[Exception] = []

    def run_server() -> None:
        try:
            server_results.append(
                serve(
                    "tcp",
                    "127.0.0.1",
                    0,
                    timeout=5.0,
                    max_messages=client_count * messages_per_client,
                    ready=ready.put_nowait,
                )
            )
        except Exception as error:
            server_errors.append(error)

    server = threading.Thread(target=run_server, name="envelope-e2e-self-test-server", daemon=True)
    server.start()
    try:
        port = ready.get(timeout=1.0)
    except queue.Empty as error:
        server.join(1.0)
        detail = type(server_errors[0]).__name__ if server_errors else "readiness timeout"
        raise AgentError(f"concurrent TCP self-test server failed: {detail}") from error

    connected = threading.Barrier(client_count)
    first_markers_sent = threading.Barrier(client_count)
    all_markers_acknowledged = threading.Barrier(client_count)
    client_results: list[list[int] | None] = [None] * client_count
    client_errors: list[str | None] = [None] * client_count
    barriers = (connected, first_markers_sent, all_markers_acknowledged)

    def run_client(index: int) -> None:
        flow_id = f"selftest-flow-{index:02d}"
        connection_id = f"selftest-connection-{index:02d}"
        deadline = time.monotonic() + 4.0
        sequences: list[int] = []
        try:
            with _client_socket("tcp", "127.0.0.1", port, "127.0.0.1", 0, deadline) as connection:
                reader = _FrameReader(connection)
                connected.wait(timeout=_remaining(deadline))
                _send_tcp(connection, _marker(flow_id, connection_id, 0, "marker"), deadline)
                first_markers_sent.wait(timeout=_remaining(deadline))
                first_ack = _decode_frame(reader.receive(deadline), expected_kinds={"ack"})
                _validate_ack(first_ack, flow_id, connection_id, 0)
                sequences.append(0)
                _send_tcp(connection, _marker(flow_id, connection_id, 1, "marker"), deadline)
                second_ack = _decode_frame(reader.receive(deadline), expected_kinds={"ack"})
                _validate_ack(second_ack, flow_id, connection_id, 1)
                sequences.append(1)
                all_markers_acknowledged.wait(timeout=_remaining(deadline))
                client_results[index] = sequences
        except Exception as error:
            client_errors[index] = f"{type(error).__name__}: {error}"
            for barrier in barriers:
                try:
                    barrier.abort()
                except threading.BrokenBarrierError:
                    pass

    clients = [
        threading.Thread(target=run_client, args=(index,), name=f"envelope-e2e-self-test-{index:02d}", daemon=True)
        for index in range(client_count)
    ]
    for client in clients:
        client.start()
    for client in clients:
        client.join(6.0)
    server.join(6.0)

    if any(client.is_alive() for client in clients) or server.is_alive():
        raise AgentError("concurrent TCP self-test did not shut down cleanly")
    failures = [error for error in client_errors if error is not None]
    if failures:
        raise AgentError(f"concurrent TCP self-test client failed: {failures[0]}")
    if server_errors:
        raise AgentError(f"concurrent TCP self-test server failed: {server_errors[0]}")
    if len(server_results) != 1:
        raise AgentError("concurrent TCP self-test returned no aggregate")
    result = server_results[0]
    expected_flow_ids = [f"selftest-flow-{index:02d}" for index in range(client_count)]
    if (
        result.get("messages") != client_count * messages_per_client
        or result.get("connections") != client_count
        or result.get("flow_ids") != expected_flow_ids
        or client_results != [[0, 1] for _index in range(client_count)]
    ):
        raise AgentError("concurrent TCP self-test aggregate is incorrect")
    return {
        "clients": client_count,
        "connections": result["connections"],
        "flow_ids": result["flow_ids"],
        "messages": result["messages"],
        "operation": "self-test",
        "success": True,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="operation", required=True)

    serve_parser = subparsers.add_parser("serve", help="serve bounded marker acknowledgements")
    serve_parser.add_argument("--protocol", choices=("tcp", "udp"), required=True)
    serve_parser.add_argument("--bind", dest="bind_ip", default="0.0.0.0")
    serve_parser.add_argument("--port", type=int, required=True)
    serve_parser.add_argument("--timeout", type=float, default=30.0)
    serve_parser.add_argument("--max-messages", type=int, default=1)

    def add_client_arguments(client_parser: argparse.ArgumentParser) -> None:
        client_parser.add_argument("--protocol", choices=("tcp", "udp"), required=True)
        client_parser.add_argument("--host", required=True)
        client_parser.add_argument("--port", type=int, required=True)
        client_parser.add_argument("--source-ip", default="0.0.0.0")
        client_parser.add_argument("--source-port", type=int, required=True)
        client_parser.add_argument("--flow-id", required=True)
        client_parser.add_argument("--timeout", type=float, default=30.0)

    probe_parser = subparsers.add_parser("probe", help="send one marker and require its acknowledgement")
    add_client_arguments(probe_parser)

    stream_parser = subparsers.add_parser("stream", help="send monotonic markers over one socket")
    add_client_arguments(stream_parser)
    stream_parser.add_argument("--count", type=int, required=True)
    stream_parser.add_argument("--interval", type=float, default=0.1)

    subparsers.add_parser("self-test", help="run the bounded concurrent TCP loopback test")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.operation == "serve":
            result = serve(
                args.protocol,
                args.bind_ip,
                args.port,
                timeout=args.timeout,
                max_messages=args.max_messages,
            )
        elif args.operation == "probe":
            result = probe(
                args.protocol,
                args.host,
                args.port,
                source_ip=args.source_ip,
                source_port=args.source_port,
                flow_id=args.flow_id,
                timeout=args.timeout,
            )
        elif args.operation == "stream":
            result = stream(
                args.protocol,
                args.host,
                args.port,
                source_ip=args.source_ip,
                source_port=args.source_port,
                flow_id=args.flow_id,
                count=args.count,
                interval=args.interval,
                timeout=args.timeout,
            )
        elif args.operation == "self-test":
            result = self_test()
        else:
            raise AgentError(f"unknown operation: {args.operation}")
    except AgentError as error:
        print(json.dumps({"error": str(error), "success": False}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
