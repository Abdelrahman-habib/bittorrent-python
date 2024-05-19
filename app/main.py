import json
import os
import sys
import bencodepy
import hashlib
# import requests - available if you need it!


# json.dumps() can't handle bytes, but bencoded "strings" need to be
# bytestrings since they might contain non utf-8 characters.
# Let's convert them to strings for printing to the console.
def bytes_to_str(data):
    if isinstance(data, bytes):
        return data.decode()
    raise TypeError(f"Type not serializable: {type(data)}")


def decode_bencode(bencoded_value):
    return bencodepy.Bencode(encoding="utf-8").decode(bencoded_value)


def decode_metainfo_file(filepath):
    metadata = bencodepy.Bencode().read(filepath)
    info = metadata.get(b"info", {})
    length = info.get(b"length")
    info_hash = hashlib.sha1(bencodepy.encode(info)).hexdigest()
    tracker_url = metadata.get(b"announce").decode("utf-8")
    piece_length = info.get(b"piece length", 0)
    pieces = info.get(b"pieces")
    piece_hashes = [pieces[i : i + 20].hex() for i in range(0, len(pieces), 20)]
    return (tracker_url, length, info_hash, piece_length, piece_hashes)

def main():
    command = sys.argv[1]

    if command == "decode":
        bencoded_value = sys.argv[2].encode()
        print(json.dumps(decode_bencode(bencoded_value), default=bytes_to_str))
    elif command == "info":
        filepath = sys.argv[2]
        try:
            os.path.exists(filepath)
            filepath = os.path.abspath(filepath)
        except:
            raise NotImplementedError("File not found")
        tracker_url, length, info_hash, piece_length, piece_hashes = decode_metainfo_file(filepath)
        print("Tracker URL:", tracker_url, "\nLength:", length, "\nInfo Hash:", info_hash, "\nPiece Length:", piece_length, "\nPiece Hashes:")
        for piece_hash in piece_hashes:
            print(piece_hash)   
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
