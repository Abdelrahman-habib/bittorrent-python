# Torrent Client

This repository contains a Python-based torrent client that allows you to decode torrent files, retrieve information, find peers, perform handshakes with peers, download specific pieces, and download entire torrent files.

## Features

- **Decode Bencode**: Decode bencoded data.
- **Retrieve Torrent Info**: Get tracker URL, file length, info hash, piece length, and piece hashes from a torrent file.
- **Get Peers**: Retrieve a list of peers from the tracker.
- **Establish Handshake**: Perform a handshake with a peer.
- **Download Piece**: Download a specific piece of a torrent file.
- **Download Torrent**: Download the entire torrent file from peers.

## Requirements

- Python 3.x
- Required packages: `requests`, `bencodepy`

Install the required packages using pip:

```bash
pip install requests bencodepy
```
## Usage
The torrent client supports several commands. Below are examples of how to use each command.

1. Decode Bencode
Decode a bencoded value and print it as JSON.

```bash
python torrent_client.py decode <bencoded_value>
```
2. Retrieve Torrent Info
Retrieve and display information from a .torrent file.

```bash
python torrent_client.py info <path_to_torrent_file>
```
3. Get Peers
Retrieve and display a list of peers from the tracker.

```bash
python torrent_client.py peers <path_to_torrent_file>
```

4. Establish Handshake
Perform a handshake with a peer and display the peer ID.

```bash
python torrent_client.py handshake <path_to_torrent_file> <peer_ip:peer_port>
```

5. Download Piece
Download a specific piece of a torrent file and save it to an output file.

```bash
python torrent_client.py download_piece <path_to_torrent_file> <output_file> <piece_index>
```

6. Download Torrent
Download the entire torrent file and save it to an output file.

```bash
python torrent_client.py download <path_to_torrent_file> <output_file>
```

## Example
Here's an example of downloading a specific piece of a torrent file:

```bash
python torrent_client.py download_piece example.torrent piece_0.tmp 0
```
And an example of downloading the entire torrent file:

```bash
python torrent_client.py download example.torrent output_file
```

Notes
Make sure to customize the `<path_to_torrent_file>`, `<peer_ip:peer_port>`, `<output_file>`, `<piece_index>`, etc., with appropriate values when using the commands.





