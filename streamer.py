# do not import anything else from loss_socket besides LossyUDP
from lossy_socket import LossyUDP

# do not import anything else from socket except INADDR_ANY
from socket import INADDR_ANY

from math import ceil

from struct import Struct

from threading import Thread, Lock
from time import sleep, time
from hashlib import blake2s
from collections import deque
from itertools import islice


class Streamer:

    CHUNK_SIZE = 1024
    ACK_TIMEOUT = 0.1
    SLEEP_INTERVAL = 0.01
    MAX_RESEND = 8

    def __init__(self, dst_ip, dst_port, src_ip=INADDR_ANY, src_port=0):
        """Default values listen on all network interfaces, chooses a random
        source port, and does not introduce any simulated packet loss."""
        self.bfl = Lock()
        self.socket = LossyUDP()
        self.socket.bind((src_ip, src_port))
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.dst = (self.dst_ip, self.dst_port)
        self.in_buffer = deque()
        self.out_buffer = deque()
        self.nextseqnum = 1
        self.nextrecseqnum = 1
        self.base = 1
        self.sendpkt = Header(b"", 0, ack=True).pack()
        self.closed = False
        self.finack = False
        self.timeout_start = time()
        self.next_new_seq_num = 1
        self.listener = Thread(target=self.th_listener)
        self.resender = Thread(target=self.th_resender)

        self.listener.start()
        self.resender.start()

    def send(self, data_bytes: bytes) -> None:
        """Note that data_bytes can be larger than one packet."""

        num_packets = ceil(len(data_bytes) / self.CHUNK_SIZE)

        def make_packet_at_i(i: int) -> bytes:
            start = i * self.CHUNK_SIZE
            end = min(start + self.CHUNK_SIZE, len(data_bytes))

            packet_data = data_bytes[start:end]
            packet_header = Header(packet_data, self.next_new_seq_num).pack()
            self.next_new_seq_num += 1
            return packet_header + packet_data

        # self.bfl.acquire()
        # while len(self.out_buffer) > 25:
        #     self.bfl.release()
        #     sleep(SLEEP_INTERVAL)
        #     self.bfl.acquire()
        with self.bfl:
            self.out_buffer.extend(map(make_packet_at_i, range(num_packets)))
        # self.bfl.release()

        while self.nextseqnum - self.base < len(self.out_buffer):
            # print("transmitting")
            with self.bfl:
                self.socket.sendto(
                    self.out_buffer[self.nextseqnum - self.base], self.dst
                )
                if self.base == self.nextseqnum:
                    self.timeout_start = time()
                self.nextseqnum += 1

    def th_resender(self) -> None:
        while not self.closed:
            try:
                if time() - self.timeout_start > self.ACK_TIMEOUT:
                    if self.nextseqnum - self.base != 0:
                        with self.bfl:
                            print(f"resending {self.nextseqnum - self.base} packets")
                            for pkt in islice(
                                self.out_buffer,
                                min(self.nextseqnum - self.base, self.MAX_RESEND),
                            ):
                                self.socket.sendto(pkt, self.dst)
                    self.timeout_start = time()
                sleep(self.SLEEP_INTERVAL)
            except Exception as e:
                print("resender died!")
                print(e)

    def recv(self) -> bytes:
        """Blocks (waits) if no data is ready to be read from the connection"""

        data = None

        while True:
            try:
                with self.bfl:
                    header, data = self.in_buffer.popleft()
                return data
            except IndexError:
                sleep(self.SLEEP_INTERVAL)

    def th_listener(self):
        while not self.closed:
            try:
                # print("hiii")
                data, _addr = self.socket.recvfrom()
                if data:
                    header = Header.unpack_from(data)
                    new_data = data[Header.size() :]

                    recreated_header = Header(
                        new_data, header.seq_num, ack=header.ack, fin=header.fin
                    )
                    # print(f"got seq={header.seq_num} ack={header.ack}")
                    if recreated_header.hash == header.hash:
                        # print(f"got {header.seq_num} with base {self.base}")
                        if header.ack and header.seq_num >= self.base:
                            with self.bfl:
                                if header.fin:
                                    self.finack = True
                                else:
                                    # print(f"processing new ACK for {header.seq_num}")
                                    for _ in range((header.seq_num - self.base) + 1):
                                        self.out_buffer.popleft()
                                self.base = header.seq_num + 1
                                self.timeout_start = time()
                        elif not header.ack:
                            # print(f"got new packet seq={header.seq_num}")
                            with self.bfl:
                                if header.seq_num == self.nextrecseqnum:
                                    # print("    want it")
                                    self.sendpkt = Header(
                                        b"",
                                        self.nextrecseqnum,
                                        ack=True,
                                        fin=header.fin,
                                    ).pack()
                                    # print(f"ACKing {self.nextrecseqnum}")
                                    self.socket.sendto(self.sendpkt, self.dst)
                                    self.nextrecseqnum += 1
                                    self.in_buffer.append((header, new_data))
                                else:
                                    # print("    dant it")
                                    # print(f"ACKing {self.nextrecseqnum - 1}")
                                    self.socket.sendto(self.sendpkt, self.dst)
                                    # sleep(SLEEP_INTERVAL)

            except Exception as e:
                print("listener died!")
                print(e)

    def close(self) -> None:
        """Cleans up. It should block (wait) until the Streamer is done with
        all the necessary ACKs and retransmissions"""
        # print("closing!")
        while self.base != self.nextseqnum:
            # print("waiting for all transmissions to finish")
            sleep(self.SLEEP_INTERVAL)

        self.finack = False

        while not self.finack:
            # print("waiting for finack")
            with self.bfl:
                self.socket.sendto(
                    Header(b"", self.nextseqnum, fin=True).pack(), self.dst
                )
                self.nextseqnum += 1

            start = time()
            while (not self.finack) and (time() - start < self.ACK_TIMEOUT):
                sleep(self.SLEEP_INTERVAL)

        sleep(2)

        self.closed = True
        self.socket.stoprecv()
        self.listener.join()
        self.resender.join()


class Header:
    PACKER = Struct("!L??QQxx")
    NO_HASH = b"\x00" * 16

    def __init__(
        self,
        data: bytes,
        seq_num: int,
        ack: bool = False,
        fin: bool = False,
        hash: bool = True,
    ):
        if hash:
            tmp_header_data = Header(b"", seq_num, ack=ack, fin=fin, hash=False).pack()
            hash_val = hash_bytes(tmp_header_data + data)
        else:
            hash_val = self.NO_HASH
        self.seq_num = seq_num
        self.ack = ack
        self.fin = fin
        self.hash = hash_val

    def pack(self) -> bytes:
        high, low = bytes_to_quads(self.hash)
        return self.PACKER.pack(self.seq_num, self.ack, self.fin, high, low)

    @classmethod
    def unpack_from(cls, data: bytes):
        seq_num, ack, fin, hash_high, hash_low = cls.PACKER.unpack_from(data)
        header = Header(b"", seq_num, ack=ack, fin=fin)
        header.hash = quads_to_bytes(hash_high, hash_low)
        return header

    @classmethod
    def size(cls) -> int:
        return cls.PACKER.size

    def __str__(self):
        return (
            f"Header(\n"
            f"  seq_num={self.seq_num},\n"
            f"  ack={self.ack},\n"
            f"  fin={self.fin},\n"
            f"  hash={self.hash.hex()}\n"
            f")"
        )


def hash_bytes(data: bytes) -> bytes:
    return blake2s(data, digest_size=16).digest()


def bytes_to_quads(hash: bytes) -> (int, int):
    if len(hash) != 16:
        raise Exception("the input to bytes_to_quads must be 16 bytes")

    high_order = int.from_bytes(hash[0:8], byteorder="big")
    low_order = int.from_bytes(hash[8:16], byteorder="big")
    return high_order, low_order


def quads_to_bytes(high_order: int, low_order: int) -> bytes:
    high_bytes = high_order.to_bytes(8, byteorder="big")
    low_bytes = low_order.to_bytes(8, byteorder="big")
    return high_bytes + low_bytes


def extract_seq(data: bytes) -> int:
    header = Header.unpack_from(data)
    return header.seq_num
