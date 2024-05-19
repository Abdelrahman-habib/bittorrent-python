import json
import os
import struct
import sys
from urllib.parse import urlencode
import bencodepy
import hashlib
import requests


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
        for i in range(0, len(peers), 6):
            ip = ".".join(str(b) for b in peers[i : i + 4])
            port = struct.unpack("!H", peers[i + 4 : i + 6])[0]
            print(f"{ip}:{port}")
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
