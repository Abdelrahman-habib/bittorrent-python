import json
import math
import os
import struct
import sys
from urllib.parse import urlencode
import bencodepy
import hashlib
import requests
import socket


def get_peers(tracker_url, info_hash, left=0,peer_id = hashlib.sha256(os.urandom(16)).hexdigest()[:20], port=6881):
    """Get peers from a tracker"""
    params = {
        "info_hash": info_hash,
        "peer_id": peer_id,
        "port": port,
        "uploaded": 0,
        "downloaded": 0,
        "left": left,
        "compact": 1,
    }
    response = requests.get(tracker_url, params=urlencode(params))
    if response.status_code != 200:
        raise RuntimeError(f"Failed to get peers: {response.status_code}")
    peers = decode_bencode(response.content).get("peers", b"")
    peers = [
            f"{'.'.join(str(b) for b in peers[i : i + 4])}:{struct.unpack('!H', peers[i + 4 : i + 6])[0]}"
            for i in range(0, len(peers), 6)
            ]
    return peers


# json.dumps() can't handle bytes, but bencoded "strings" need to be
# bytestrings since they might contain non utf-8 characters.
# Let's convert them to strings for printing to the console.
def bytes_to_str(data):
    if isinstance(data, bytes):
        return data.decode()
    raise TypeError(f"Type not serializable: {type(data)}")


def decode_bencode(bencoded_value):
    return bencodepy.Bencode(encoding="utf-8", encoding_fallback="all").decode(bencoded_value)


def decode_metainfo_file(filepath):
    try:
        os.path.exists(filepath)
        filepath = os.path.abspath(filepath)
    except:
        raise NotImplementedError("File not found")
    metadata = bencodepy.Bencode().read(filepath)
    info = metadata.get(b"info", {})
    length = info.get(b"length")
    info_hash = hashlib.sha1(bencodepy.encode(info)).hexdigest()
    tracker_url = metadata.get(b"announce").decode("utf-8")
    piece_length = info.get(b"piece length", 0)
    pieces = info.get(b"pieces")
    piece_hashes = [pieces[i : i + 20].hex() for i in range(0, len(pieces), 20)]
    return (info, tracker_url, length, info_hash, piece_length, piece_hashes)


def generate_handshake(info_hash,peer_id = hashlib.sha256(os.urandom(16)).hexdigest()[:20].encode()):
    """Generate the handshake message"""
    return (
        b"\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00"
        + info_hash
        + b"\x00\x00\x00\x00\x00\x00\x00\x00"
    )

def establish_peer_connection(ip, port, info_hash,peer_id = hashlib.sha256(os.urandom(16)).hexdigest()[:20].encode()):
    """Establish a handshake with a peer"""
    handshake = generate_handshake(info_hash,peer_id)
    # make request to peer
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((ip, int(port)))
        s.send(handshake)
        peer_id = s.recv(68)[48:].hex()
    return peer_id


def download_piece(torrent_file, piece_index, output_file):
    """Download a piece"""
    info,tracker_url, length, info_hash, piece_length, piece_hashes = decode_metainfo_file(torrent_file)
    my_peer_id = hashlib.sha256(os.urandom(16)).hexdigest()[:20].encode()
    peers = get_peers(tracker_url, info_hash = hashlib.sha1(bencodepy.encode(info)).digest(), left=length)
    peer = peers[1]
    peer_ip, peer_port = peer.split(":")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print("Connecting to peer", peer_ip, peer_port)
        s.connect((peer_ip, int(peer_port)))
        handshake = generate_handshake(hashlib.sha1(bencodepy.encode(info)).digest(), my_peer_id)
        s.sendall(handshake)
        response_handshake = s.recv(len(handshake))
        length, msg_type = s.recv(4), s.recv(1)
        if msg_type != b"\x05": # "choke"
            raise Exception("Expected bitfield message")
        s.recv(int.from_bytes(length, byteorder="big") - 1)
        s.sendall(b"\x00\x00\x00\x01\x02") # "unchoke"
        length, msg_type = s.recv(4), s.recv(1) # "bitfield"
        while msg_type != b"\x01": 
            length, msg_type = s.recv(4), s.recv(1)
        chuck_size = 16 * 1024
        if piece_index == (len(info["pieces"]) // 20) - 1:
            piece_length = length % piece_length
        piece = b""
        for i in range(math.ceil(piece_length / chuck_size)):
            msg_id = b"\x06"
            chunk_index = piece_index.to_bytes(4, byteorder="big")
            chunk_begin = (i * chuck_size).to_bytes(4, byteorder="big")
            if (
                i == math.ceil(piece_length / chuck_size) - 1
                and piece_length % chuck_size != 0
            ):
                chunk_length = (piece_length % chuck_size).to_bytes(4, byteorder="big")
            else:
                chunk_length = chuck_size.to_bytes(4, byteorder="big")
            message_length = (
                1 + len(chunk_index) + len(chunk_begin) + len(chunk_length)
            ).to_bytes(4, byteorder="big")
            request_message = (
                message_length + msg_id + chunk_index + chunk_begin + chunk_length
            )
            s.sendall(request_message)
            print(
                f"Requesting piece: {int.from_bytes(chunk_index, 'big')}, begin: {int.from_bytes(chunk_begin, 'big')}, length: {int.from_bytes(chunk_length, 'big')}"
            )
            msg = msg_id + chunk_index + chunk_begin + chunk_length
            msg = len(msg).to_bytes(4) + msg
            length, msg_type = int.from_bytes(s.recv(4)), s.recv(1)
            resp_index = int.from_bytes(s.recv(4))
            resp_begin = int.from_bytes(s.recv(4))
            block = b""
            to_get = int.from_bytes(chunk_length)
            while len(block) < to_get:
                block += s.recv(to_get - len(block))
            piece += block
        og_hash = info["pieces"][
            piece_index * 20 : piece_index * 20 + 20
        ]
        assert hashlib.sha1(piece).digest() == og_hash
        with open(output_file, "wb") as f:
            f.write(piece)


def main():
    command = sys.argv[1]

    if command == "decode":
        bencoded_value = sys.argv[2].encode()
        print(json.dumps(decode_bencode(bencoded_value), default=bytes_to_str))
    elif command == "info":
        filepath = sys.argv[2]
        info,tracker_url, length, info_hash, piece_length, piece_hashes = decode_metainfo_file(filepath)
        print("Tracker URL:", tracker_url, "\nLength:", length, "\nInfo Hash:", info_hash, "\nPiece Length:", piece_length, "\nPiece Hashes:")
        for piece_hash in piece_hashes:
            print(piece_hash)
    elif command == "peers":
        filepath = sys.argv[2]
        info,tracker_url, length, info_hash, piece_length, piece_hashes = decode_metainfo_file(filepath)
        peers = get_peers(tracker_url, info_hash = hashlib.sha1(bencodepy.encode(info)).digest(), left=length)
        for peer in peers:
            print(peer)
    elif command == "handshake":
        filepath = sys.argv[2]
        (ip, port) = sys.argv[3].split(":")
        info,tracker_url, length, info_hash, piece_length, piece_hashes = decode_metainfo_file(filepath)
        peer_id = establish_peer_connection(ip, port, info_hash = hashlib.sha1(bencodepy.encode(info)).digest())
        print(f"Peer ID: {peer_id}")
    elif command == "download_piece":
        output_file = sys.argv[3]
        filepath = sys.argv[4]
        piece_index = int(sys.argv[5])
        download_piece(filepath, piece_index, output_file)
        print(f"Piece {piece_index} downloaded to {output_file}.")
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
