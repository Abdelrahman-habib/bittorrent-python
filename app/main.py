import json
import os
import struct
import sys
from urllib.parse import urlencode
import bencodepy
import hashlib
import requests
import socket


def bytes_to_str(data):
    if isinstance(data, bytes):
        return data.decode()
    raise TypeError(f"Type not serializable: {type(data)}")


def decode_bencode(bencoded_value):
    return bencodepy.Bencode(encoding="utf-8", encoding_fallback="all").decode(bencoded_value)


def decode_metainfo_file(filepath):
    """
    Reads a .torrent file from disk and returns the information contained within.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError("File not found")

    filepath = os.path.abspath(filepath)
    metadata = bencodepy.Bencode().read(filepath)
    info = metadata.get(b"info", {})

    length = info.get(b"length")
    info_hash = hashlib.sha1(bencodepy.encode(info)).hexdigest()
    tracker_url = metadata.get(b"announce").decode("utf-8")
    piece_length = info.get(b"piece length")
    pieces = info.get(b"pieces")
    piece_hashes = [pieces[i:i+20].hex() for i in range(0, len(pieces), 20)]

    return info, tracker_url, length, info_hash, piece_length, piece_hashes, pieces


def get_peers(tracker_url, info_hash, peer_id=b"00112233445566778899", port=6881, uploaded=0, downloaded=0, left=0):
    """
    Contact the tracker and get a list of peers.
    """
    url = tracker_url + '?' + urlencode({
        'info_hash': info_hash,
        'peer_id': peer_id,
        'port': port,
        'uploaded': uploaded,
        'downloaded': downloaded,
        'left': left,
        'compact': 1
    })
    response = requests.get(url)
    response.raise_for_status()
    peers = decode_bencode(response.content).get(b"peers")
    peers_list = [(socket.inet_ntoa(peers[i:i+4]), struct.unpack("!H", peers[i+4:i+6])[0])
                  for i in range(0, len(peers), 6)]
    return peers_list


def establish_peer_connection(ip, port, info_hash, peer_id):
    """
    Establish a connection to a peer and perform a BitTorrent handshake.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        sock.connect((ip, int(port)))
        pstrlen = struct.pack("B", 19)
        pstr = b"BitTorrent protocol"
        reserved = b"\x00" * 8
        handshake = pstrlen + pstr + reserved + info_hash + peer_id
        sock.send(handshake)
        response = sock.recv(68)
        if response[28:48] != info_hash:
            raise ValueError("Info hash does not match")
        return response[48:68]


def download_piece(filepath, piece_index, output_file):
    """
    Download a specific piece from a torrent.
    """
    info, tracker_url, file_length, info_hash, piece_length, piece_hashes, pieces = decode_metainfo_file(filepath)
    peers = get_peers(tracker_url, info_hash=hashlib.sha1(bencodepy.encode(info)).digest(), left=file_length)
    piece_hash = bytes.fromhex(piece_hashes[piece_index])
    piece_offset = piece_index * piece_length
    piece_size = min(piece_length, file_length - piece_offset)
    piece_data = bytearray(piece_size)

    for ip, port in peers:
        try:
            peer_id = establish_peer_connection(ip, port, info_hash, b"-PC0001-000000000000")
            request = struct.pack("!IBIII", 0, 13, 6, piece_index, 0, piece_size)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                sock.connect((ip, port))
                sock.send(request)
                piece_data = sock.recv(piece_size)
                if hashlib.sha1(piece_data).digest() == piece_hash:
                    break
        except Exception as e:
            print(f"Failed to download from {ip}:{port} - {e}")

    with open(output_file, "wb") as file:
        file.write(piece_data)


def download_torrent(filepath, output_file_path):
    """
    Download all pieces of the torrent and save to output file.
    """
    info, tracker_url, file_length, info_hash, piece_length, piece_hashes, _ = decode_metainfo_file(filepath)
    downloaded_pieces = []
    peers = get_peers(tracker_url, info_hash=hashlib.sha1(bencodepy.encode(info)).digest(), left=file_length)

    for piece_index, piece_hash in enumerate(piece_hashes):
        piece_offset = piece_index * piece_length
        piece_size = min(piece_length, file_length - piece_offset)
        piece_data = bytearray(piece_size)

        for ip, port in peers:
            try:
                peer_id = establish_peer_connection(ip, port, info_hash, b"-PC0001-000000000000")
                request = struct.pack("!IBIII", 0, 13, 6, piece_index, 0, piece_size)
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(5)
                    sock.connect((ip, port))
                    sock.send(request)
                    piece_data = sock.recv(piece_size)
                    if hashlib.sha1(piece_data).digest() == bytes.fromhex(piece_hash):
                        downloaded_pieces.append(piece_data)
                        break
            except Exception as e:
                print(f"Failed to download piece {piece_index} from {ip}:{port} - {e}")

    with open(output_file_path, "wb") as output_file:
        for piece in downloaded_pieces:
            output_file.write(piece)


def main():
    command = sys.argv[1]

    if command == "decode":
        bencoded_value = sys.argv[2].encode()
        print(json.dumps(decode_bencode(bencoded_value), default=bytes_to_str))
    elif command == "info":
        filepath = sys.argv[2]
        info, tracker_url, length, info_hash, piece_length, piece_hashes, pieces = decode_metainfo_file(filepath)
        print("Tracker URL:", tracker_url, "\nLength:", length, "\nInfo Hash:", info_hash, "\nPiece Length:", piece_length, "\nPiece Hashes:")
        for piece_hash in piece_hashes:
            print(piece_hash)
    elif command == "peers":
        filepath = sys.argv[2]
        info, tracker_url, length, info_hash, piece_length, piece_hashes, pieces = decode_metainfo_file(filepath)
        peers = get_peers(tracker_url, info_hash=hashlib.sha1(bencodepy.encode(info)).digest(), left=length)
        for peer in peers:
            print(peer)
    elif command == "handshake":
        filepath = sys.argv[2]
        (ip, port) = sys.argv[3].split(":")
        info, tracker_url, length, info_hash, piece_length, piece_hashes, pieces = decode_metainfo_file(filepath)
        peer_id = establish_peer_connection(ip, port, info_hash=hashlib.sha1(bencodepy.encode(info)).digest(), peer_id=b"00112233445566778899")
        print(f"Peer ID: {peer_id}")
    elif command == "download_piece":
        output_file = sys.argv[3]
        filepath = sys.argv[4]
        piece_index = int(sys.argv[5])
        download_piece(filepath, piece_index, output_file)
        print(f"Piece {piece_index} downloaded to {output_file}.")
    elif command == "download":
        output_file = sys.argv[3]
        torrent_file = sys.argv[4]
        download_torrent(torrent_file, output_file)
        print(f"Downloaded {torrent_file} to {output_file}.")
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
