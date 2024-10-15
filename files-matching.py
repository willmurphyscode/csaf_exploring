import tarfile
import zstandard as zstd
import subprocess
import sys

# Path to the .tar.zst file
archive_path = "csaf_vex_2024-10-06.tar.zst"

# Strings to search for
search_terms = ["first_affected", "first_fixed"]


def search_in_file(file_obj, file_name, search_terms):
    """Search the given file object with ripgrep in chunks."""
    # Build the ripgrep command, specifying the patterns to search for
    rg_command = ["rg", "--quiet"] + search_terms

    # Create the ripgrep process with subprocess
    try:
        process = subprocess.Popen(
            rg_command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        # Read the file in chunks and pass it to ripgrep's stdin
        chunk_size = 8192  # 8KB chunks
        while chunk := file_obj.read(chunk_size):
            process.stdin.write(chunk)
            process.stdin.flush()

        # Close stdin to signal to ripgrep that the input is complete
        process.stdin.close()

        # Wait for the ripgrep process to finish and check the result
        process.wait()
        return process.returncode == 0  # True if ripgrep found a match
    except subprocess.CalledProcessError as e:
        print(f"Error running ripgrep: {e}", file=sys.stderr)
        return False
    except BrokenPipeError as e:
        print(f"broken pipe on {file_name} {e}", file=sys.stderr)
        return process.returncode == 0


def main(archive_path, pattern):
    # Open the compressed .tar.zst file
    with open(archive_path, "rb") as compressed_file:
        # Initialize the decompressor
        dctx = zstd.ZstdDecompressor()

        # Decompress the .tar.zst into a stream
        with dctx.stream_reader(compressed_file) as decompressed_stream:
            # Wrap the decompressed stream into a file-like object
            with tarfile.open(fileobj=decompressed_stream, mode="r|") as tar:
                # Iterate through the files in the archive
                for member in tar:
                    # We only care about .json files
                    if member.isfile() and member.name.endswith(".json"):
                        # Open the file object within the archive
                        file_obj = tar.extractfile(member)
                        if file_obj is not None:
                            # Search the file for the terms
                            # print(f"searching {member.name}", file=sys.stderr)
                            if search_in_file(file_obj, member.name, [pattern]):
                                print(f"Found in file: {member.name}")
                    else:
                        print(f"skipping {member.name}", file=sys.stderr)


if __name__ == "__main__":
    cmd, file, pattern = sys.argv
    if not file or not pattern:
        print(f"Usage: {cmd} FILE PATTERN", file=sys.stderr)
        sys.exit(1)
    main(file, pattern)
