# do not import anything else from loss_socket besides LossyUDP
from lossy_socket import LossyUDP

# do not import anything else from socket except INADDR_ANY
from socket import INADDR_ANY

from math import ceil

from struct import Struct

from threading import Thread
from time import sleep, time
from hashlib import blake2s, md5
from collections import deque
from itertools import islice

CHUNK_SIZE = 1024
ACK_TIMEOUT = 0.25
SLEEP_INTERVAL = 0.001
NO_HASH = b"\x00" * 16


class Streamer:
    def __init__(self, dst_ip, dst_port, src_ip=INADDR_ANY, src_port=0):
        """Default values listen on all network interfaces, chooses a random
        source port, and does not introduce any simulated packet loss."""
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
        self.listener = Thread(target=self.listener)
        self.listener.start()
        self.acknum = 0
        self.ack = False
        self.finack = False
        self.start = time()
        self.next_new_seq_num = 1

    def send(self, data_bytes: bytes) -> None:
        """Note that data_bytes can be larger than one packet."""

        num_packets = ceil(len(data_bytes) / CHUNK_SIZE)

        def make_packet_at_i(i: int) -> bytes:
            start = i * CHUNK_SIZE
            end = min(start + CHUNK_SIZE, len(data_bytes))

            packet_data = data_bytes[start:end]
            packet_header = Header(packet_data, self.next_new_seq_num).pack()
            self.next_new_seq_num += 1
            return packet_header + packet_data

        self.out_buffer.extend(map(make_packet_at_i, range(num_packets)))

        while len(self.out_buffer) > 0:

            if time() - self.start > ACK_TIMEOUT:
                self.start = time()
                for pkt in islice(self.out_buffer, self.nextseqnum - self.base):
                    self.socket.sendto(pkt, self.dst)
            elif self.ack:
                for _ in range(self.acknum - self.base + 1):
                    self.out_buffer.popleft()

                self.base = self.acknum + 1
                self.ack = False
                self.start = time()
            elif self.nextseqnum - self.base < len(self.out_buffer):
                self.socket.sendto(self.out_buffer[self.nextseqnum - self.base], self.dst)
                if self.base == self.nextseqnum:
                    self.start = time()
                self.nextseqnum += 1
            else:
                sleep(SLEEP_INTERVAL)

    def recv(self) -> bytes:
        """Blocks (waits) if no data is ready to be read from the connection"""

        data = None

        while True:
            try:
                header, data = self.in_buffer.popleft()
                return data
            except IndexError:
                sleep(SLEEP_INTERVAL)

    def listener(self):
        while not self.closed:
            try:
                data, _addr = self.socket.recvfrom()
                if data:
                    header = Header.unpack_from(data)
                    new_data = data[Header.size() :]

                    recreated_header = Header(
                        new_data,
                        header.seq_num,
                        ack=header.ack,
                        fin=header.fin,
                    )

                    if recreated_header.hash == header.hash:
                        if header.ack:
                            self.ack = True
                            self.acknum = header.seq_num
                            if header.fin:
                                self.finack = True
                        elif header.fin:
                            self.socket.sendto(Header(b"", header.seq_num, ack=True, fin=True).pack(), self.dst)
                        else:
                            if header.seq_num == self.nextrecseqnum:
                                self.sendpkt = Header(b"", self.nextrecseqnum, ack=True, fin=header.fin).pack()
                                self.socket.sendto(self.sendpkt, self.dst)
                                self.nextrecseqnum += 1
                                self.in_buffer.append((header, new_data))
                            else:
                                self.socket.sendto(self.sendpkt, self.dst)


            except Exception as e:
                print("listener died!")
                print(e)

    def close(self) -> None:
        """Cleans up. It should block (wait) until the Streamer is done with
        all the necessary ACKs and retransmissions"""
        print("closing!")
        while self.base != self.nextseqnum:
            sleep(SLEEP_INTERVAL)

        self.finack = False

        while not self.finack:
            self.socket.sendto(
                Header(b"", self.nextseqnum, fin=True).pack(), self.dst
            )

            start = time()
            while (not self.finack) and (time() - start < ACK_TIMEOUT):
                sleep(SLEEP_INTERVAL)

        sleep(2)

        self.closed = True
        self.socket.stoprecv()
        self.listener.join()


class Header:
    PACKER = Struct("!L??QQxx")

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
            hash_val = NO_HASH
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


def hash_bytes(data: bytes) -> bytes:
    return md5(data).digest()


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


