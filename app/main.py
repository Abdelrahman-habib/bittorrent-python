import json
import os
import sys
import bencodepy
# import requests - available if you need it!


# json.dumps() can't handle bytes, but bencoded "strings" need to be
# bytestrings since they might contain non utf-8 characters.
# Let's convert them to strings for printing to the console.
def bytes_to_str(data):
    if isinstance(data, bytes):
        return data.decode()
    raise TypeError(f"Type not serializable: {type(data)}")

# Examples:
#
# - decode_bencode(b"5:hello") -> b"hello"
# - decode_bencode(b"10:hello12345") -> b"hello12345"
# - decode_bencode(b"i12345e") -> 12345
def decode_bencode(bencoded_value):
    return bencodepy.Bencode(encoding="utf-8").decode(bencoded_value)


def decode_metainfo_file(filepath):
    metadata = bencodepy.Bencode(encoding="utf-8").read(filepath)
    tracker_url = metadata.get(b"announce").decode("utf-8")
    length = metadata.get(b"info", {}).get(b"length")
    return (tracker_url, length)

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
        tracker_url, length = decode_metainfo_file(filepath)
        print("Tracker URL:", tracker_url, "\nLength:", length)
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
