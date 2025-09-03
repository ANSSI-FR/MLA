import hashlib
import os
import io
import pytest
import tempfile
from typing import Any, Dict, Type

import mla
from mla import MLAReader, MLAWriter, EntryName


# Test data
FILES: Dict[EntryName, bytes] = {
    EntryName("file1"): b"DATA1",
    EntryName("file2"): b"DATA_2",
}


@pytest.fixture
def basic_archive() -> str:
    "Create a temporary archive and return its path"
    fname: str = tempfile.mkstemp(suffix=".mla")[1]
    with MLAWriter(
        fname, mla.WriterConfig.without_encryption_without_signature()
    ) as archive:
        for name, data in FILES.items():
            archive[name] = data
    return fname


def test_bad_mode() -> None:
    "Ensure MLAWriter/MLAReader with wrong config type raises error"
    target_file: str = "/tmp/must_not_exists"
    with pytest.raises(TypeError):
        MLAWriter(target_file, "NOT_A_CONFIG")  # type: ignore
    with pytest.raises(TypeError):
        MLAReader(target_file, "NOT_A_CONFIG")  # type: ignore
    # File should not have been created
    with pytest.raises(FileNotFoundError):
        open(target_file)


def test_repr() -> None:
    "Ensure the repr is correct"
    path: str = tempfile.mkstemp(suffix=".mla")[1]

    with MLAWriter(
        path, mla.WriterConfig.without_encryption_without_signature()
    ) as archive:
        assert repr(archive) == f"<MLAWriter path='{path}'>"
        # finalize called automatically on context exit

    with MLAReader(
        path,
        mla.ReaderConfig.without_encryption(
            mla.SignatureConfig.without_signature_verification()
        ),
    ) as archive:
        assert repr(archive) == f"<MLAReader path='{path}'>"


def test_forbidden_in_write_mode() -> None:
    "Ensure read-only API cannot be called in write mode"
    archive = MLAWriter(
        tempfile.mkstemp(suffix=".mla")[1],
        mla.WriterConfig.without_encryption_without_signature(),
    )
    for method in ["keys", "list_entries", "__contains__", "__getitem__", "__len__"]:
        with pytest.raises(AttributeError):
            getattr(archive, method)


def test_forbidden_in_read_mode(basic_archive: str) -> None:
    "Ensure write-only API cannot be called in read mode"
    archive = MLAReader(
        basic_archive,
        mla.ReaderConfig.without_encryption(
            mla.SignatureConfig.without_signature_verification()
        ),
    )
    # __setitem__
    with pytest.raises(TypeError):
        archive[EntryName("file")] = b"data"  # type: ignore
    # .finalize
    with pytest.raises(AttributeError):
        archive.finalize()  # type: ignore


def test_read_api(basic_archive: str) -> None:
    "Test basics read APIs"
    archive = MLAReader(
        basic_archive,
        mla.ReaderConfig.without_encryption(
            mla.SignatureConfig.without_signature_verification()
        ),
    )
    # Compare string representations of keys instead of EntryName objects,
    # because EntryName instances don't support direct comparison
    assert sorted(
        name.raw_content_to_escaped_string() for name in archive.keys()
    ) == sorted(name.raw_content_to_escaped_string() for name in FILES.keys())
    # __contains__
    assert EntryName("file1") in archive
    assert EntryName("file3") not in archive
    # __getitem__
    assert archive[EntryName("file1")] == FILES[EntryName("file1")]
    assert archive[EntryName("file2")] == FILES[EntryName("file2")]
    with pytest.raises(KeyError):
        archive[EntryName("file3")]
    # __len__
    assert len(archive) == 2


def test_list_entries(basic_archive: str) -> None:
    "Test list files possibilities"
    archive = MLAReader(
        basic_archive,
        mla.ReaderConfig.without_encryption(
            mla.SignatureConfig.without_signature_verification()
        ),
    )
    # Basic
    # Compare string representations of keys instead of EntryName objects,
    # because EntryName instances don't support direct comparison
    assert sorted(
        name.raw_content_to_escaped_string() for name in archive.list_entries()
    ) == sorted(name.raw_content_to_escaped_string() for name in FILES.keys())

    # With size
    size_entries = archive.list_entries(include_size=True)
    if isinstance(size_entries, dict):
        size_items = [(name, info.size) for name, info in size_entries.items()]
    else:
        size_items = [(name, 0) for name in size_entries]
    expected_size_items = [(name, len(data)) for name, data in FILES.items()]
    assert sorted(size_items) == sorted(expected_size_items)

    # With hash
    hash_entries = archive.list_entries(include_hash=True)
    if isinstance(hash_entries, dict):
        hash_items = [(name, info.hash) for name, info in hash_entries.items()]
    else:
        hash_items = [(name, b"") for name in hash_entries]
    expected_hash_items = [
        (name, hashlib.sha256(data).digest()) for name, data in FILES.items()
    ]
    assert sorted(hash_items) == sorted(expected_hash_items)

    # With size and hash
    size_hash_entries = archive.list_entries(include_size=True, include_hash=True)
    if isinstance(size_hash_entries, dict):
        size_hash_items = [
            (name, info.size, info.hash)
            for name, info in size_hash_entries.items()
        ]
    else:
        size_hash_items = [(name, 0, b"") for name in size_hash_entries]
    expected_size_hash_items = [
        (name, len(data), hashlib.sha256(data).digest())
        for name, data in FILES.items()
    ]
    assert sorted(size_hash_items) == sorted(expected_size_hash_items)


def test_write_api() -> None:
    "Test basics write APIs"
    path: str = tempfile.mkstemp(suffix=".mla")[1]
    writer_archive = MLAWriter(
        path, mla.WriterConfig.without_encryption_without_signature()
    )

    # __setitem__
    for name, data in FILES.items():
        writer_archive[name] = data

    # close
    writer_archive.finalize()

    # Check the resulting archive with a reader
    reader_archive = MLAReader(
        path,
        mla.ReaderConfig.without_encryption(
            mla.SignatureConfig.without_signature_verification()
        ),
    )
    # Compare string representations of keys instead of EntryName objects,
    # because EntryName instances don't support direct comparison
    assert sorted(
        name.raw_content_to_escaped_string() for name in reader_archive.keys()
    ) == sorted(name.raw_content_to_escaped_string() for name in FILES.keys())
    assert reader_archive[EntryName("file1")] == FILES[EntryName("file1")]
    assert reader_archive[EntryName("file2")] == FILES[EntryName("file2")]


def test_double_write() -> None:
    "Rewriting the file must raise an MLA error"
    archive = MLAWriter(
        tempfile.mkstemp(suffix=".mla")[1],
        mla.WriterConfig.without_encryption_without_signature(),
    )
    archive[EntryName("file1")] = FILES[EntryName("file1")]
    with pytest.raises(mla.DuplicateEntryName):
        archive[EntryName("file1")] = FILES[EntryName("file1")]


def test_context_read(basic_archive: str) -> None:
    "Test reading using a `with` statement (context management protocol)"
    with MLAReader(
        basic_archive,
        mla.ReaderConfig.without_encryption(
            mla.SignatureConfig.without_signature_verification()
        ),
    ) as m:
        # Compare string representations of keys instead of EntryName objects,
        # because EntryName instances don't support direct comparison
        assert sorted(
            name.raw_content_to_escaped_string() for name in m.keys()
        ) == sorted(name.raw_content_to_escaped_string() for name in FILES.keys())
        for name, data in FILES.items():
            assert m[name] == data


def test_context_write() -> None:
    "Test writing using a `with` statement (context management protocol)"
    path: str = tempfile.mkstemp(suffix=".mla")[1]

    with MLAWriter(path, mla.WriterConfig.without_encryption_without_signature()) as m:
        for name, data in FILES.items():
            m[name] = data

    # Check the resulting file
    with MLAReader(
        path,
        mla.ReaderConfig.without_encryption(
            mla.SignatureConfig.without_signature_verification()
        ),
    ) as m:
        # Compare string representations of keys instead of EntryName objects,
        # because EntryName instances don't support direct comparison
        assert sorted(
            name.raw_content_to_escaped_string() for name in m.keys()
        ) == sorted(name.raw_content_to_escaped_string() for name in FILES.keys())
        for name, data in FILES.items():
            assert m[name] == data


def test_context_write_error() -> None:
    "Raise an error during the context write __exit__"
    with pytest.raises(mla.BadAPIArgument):
        with MLAWriter(
            tempfile.mkstemp(suffix=".mla")[1],
            mla.WriterConfig.without_encryption_without_signature(),
        ) as archive:
            # INTENTIONALLY BUGGY
            # .finalize will be called twice, causing an exception
            archive.finalize()


def test_context_write_error_in_with() -> None:
    "Raise an error in the with statement, it must be re-raised"

    CustomException: Type[Exception] = type("CustomException", (Exception,), {})

    with pytest.raises(CustomException):
        with MLAWriter(
            tempfile.mkstemp(suffix=".mla")[1],
            mla.WriterConfig.without_encryption_without_signature(),
        ) as m:
            # INTENTIONALLY BUGGY
            raise CustomException


def test_writer_config_compression() -> None:
    "Test compression API in WriterConfig creation"
    config = mla.WriterConfig.without_encryption_without_signature()
    with pytest.raises(OverflowError):
        config.with_compression_level(-1)
    with pytest.raises(mla.ConfigError):
        config.with_compression_level(0xFF)

    # Value
    config.with_compression_level(mla.DEFAULT_COMPRESSION_LEVEL)
    config.with_compression_level(1)

    # Chaining
    out = config.with_compression_level(mla.DEFAULT_COMPRESSION_LEVEL)
    assert out is config


# Expected: mla/bindings/python/tests/
MLA_BASE_PATH: str = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
)
SAMPLE_PATH: str = os.path.join(MLA_BASE_PATH, "samples")


def test_public_keys() -> None:
    "Test the PublicKeys object"
    # Bad parsing
    with pytest.raises(mla.InvalidKeyFormat):
        mla.PublicKeys(b"NOT A KEY")

    # This is a private key, not a public one
    with pytest.raises(mla.InvalidKeyFormat):
        mla.PublicKeys(os.path.join(SAMPLE_PATH, "test_mlakey.mlapriv"))

    # Parse a key
    with open(os.path.join(SAMPLE_PATH, "test_mlakey.mlapub"), "rb") as f:
        pkeys = mla.PublicKeys(f.read())
    assert len(pkeys.keys) == 1

    # Open several keys
    with open(os.path.join(SAMPLE_PATH, "test_mlakey.mlapub"), "rb") as f1, open(
        os.path.join(SAMPLE_PATH, "test_mlakey_2.mlapub"), "rb"
    ) as f2:
        pkeys = mla.PublicKeys(f1.read(), f2.read())
    assert len(pkeys.keys) == 2


def test_private_keys() -> None:
    "Test the PrivateKeys object"
    # Bad parsing
    with pytest.raises(mla.InvalidKeyFormat):
        mla.PrivateKeys(b"NOT A KEY")

    # This is a public key, not a private one
    with pytest.raises(mla.InvalidKeyFormat):
        mla.PrivateKeys(os.path.join(SAMPLE_PATH, "test_mlakey.mlapub"))

    # Parse a key
    with open(os.path.join(SAMPLE_PATH, "test_mlakey.mlapriv"), "rb") as f:
        pkeys = mla.PrivateKeys(f.read())
    assert len(pkeys.keys) == 1

    # Open several keys
    with open(os.path.join(SAMPLE_PATH, "test_mlakey.mlapriv"), "rb") as f1, open(
        os.path.join(SAMPLE_PATH, "test_mlakey_2.mlapriv"), "rb"
    ) as f2:
        pkeys = mla.PrivateKeys(f1.read(), f2.read())
    assert len(pkeys.keys) == 2


def test_writer_config_public_keys() -> None:
    "Test public keys API in WriterConfig creation"

    # Test API call
    with pytest.raises(mla.InvalidKeyFormat):
        mla.WriterConfig.with_encryption_without_signature(mla.PublicKeys(b"NOT A KEY"))

    # Test shortcut on object build
    with open(os.path.join(SAMPLE_PATH, "test_mlakey.mlapub"), "rb") as f:
        config = mla.WriterConfig.with_encryption_without_signature(
            mla.PublicKeys(f.read())
        )

    # Chaining
    with open(os.path.join(SAMPLE_PATH, "test_mlakey.mlapub"), "rb") as f1, open(
        os.path.join(SAMPLE_PATH, "test_mlakey_2.mlapub"), "rb"
    ) as f2:
        out = mla.WriterConfig.with_encryption_without_signature(
            mla.PublicKeys(f1.read(), f2.read())
        )


def test_mlafile_bad_config() -> None:
    "Try to create a MLAWriter/MLAReader with the wrong config parameter"
    with pytest.raises(TypeError):
        MLAWriter(tempfile.mkstemp(suffix=".mla")[1], "NOT A CONFIG")  # type: ignore
    with pytest.raises(TypeError):
        MLAWriter(
            tempfile.mkstemp(suffix=".mla")[1],
            mla.ReaderConfig.without_encryption(  # type: ignore
                mla.SignatureConfig.without_signature_verification()
            ),
        )
    with pytest.raises(TypeError):
        MLAReader(
            tempfile.mkstemp(suffix=".mla")[1],
            mla.WriterConfig.without_encryption_without_signature(),  # type: ignore
        )


def test_reader_config_api() -> None:
    "Test the ReaderConfig API"
    # Add a remove private keys
    with open(os.path.join(SAMPLE_PATH, "test_mlakey.mlapriv"), "rb") as f:
        priv_key_data = f.read()

    config = mla.ReaderConfig(
        mla.PrivateKeys(priv_key_data),
        mla.SignatureConfig.without_signature_verification(),
    )
    config = mla.ReaderConfig(
        private_keys=mla.PrivateKeys(priv_key_data),
        signature_config=mla.SignatureConfig.without_signature_verification(),
    )


def test_write_then_read_encrypted() -> None:
    "Create an encrypted archive, then read it"
    # Create the archive
    path = tempfile.mkstemp(suffix=".mla")[1]
    with MLAWriter(
        path,
        mla.WriterConfig.with_encryption_without_signature(
            mla.PublicKeys(
                open(os.path.join(SAMPLE_PATH, "test_mlakey.mlapub"), "rb").read()
            )
        ),
    ) as archive:
        for name, data in FILES.items():
            archive[name] = data

    # Read the archive
    with MLAReader(
        path,
        mla.ReaderConfig(
            private_keys=mla.PrivateKeys(
                open(os.path.join(SAMPLE_PATH, "test_mlakey.mlapriv"), "rb").read()
            ),
            signature_config=mla.SignatureConfig.without_signature_verification(),
        ),
    ) as archive:
        # Compare string representations of keys instead of EntryName objects,
        # because EntryName instances don't support direct comparison
        assert sorted(
            name.raw_content_to_escaped_string() for name in archive.keys()
        ) == sorted(name.raw_content_to_escaped_string() for name in FILES.keys())
        for name, data in FILES.items():
            assert archive[name] == data


def test_read_encrypted_archive_bad_key() -> None:
    "Try to read an encrypted archive with a bad key"
    # Create the archive
    path = tempfile.mkstemp(suffix=".mla")[1]
    with MLAWriter(
        path,
        mla.WriterConfig.with_encryption_without_signature(
            mla.PublicKeys(
                open(os.path.join(SAMPLE_PATH, "test_mlakey.mlapub"), "rb").read()
            ),
        ),
    ) as archive:
        for name, data in FILES.items():
            archive[name] = data

    # Try to read without a key
    with pytest.raises(mla.PrivateKeyNeeded):
        with MLAReader(
            path,
            mla.ReaderConfig.without_encryption(
                mla.SignatureConfig.without_signature_verification()
            ),
        ):
            pass

    # Try to read with an incorrect key (mla.ConfigError: PrivateKeyNotFound)
    with pytest.raises(mla.ConfigError):
        with MLAReader(
            path,
            mla.ReaderConfig(
                private_keys=mla.PrivateKeys(
                    open(
                        os.path.join(SAMPLE_PATH, "test_mlakey_2.mlapriv"), "rb"
                    ).read()
                ),
                signature_config=mla.SignatureConfig.without_signature_verification(),
            ),
        ):
            pass


def test_write_entry_to_str(basic_archive: str) -> None:
    """Test archive.write_entry_to(), using the String output version"""
    # Temporary directory for extraction
    tmpdir = tempfile.mkdtemp()
    with MLAReader(
        basic_archive,
        mla.ReaderConfig.without_encryption(
            mla.SignatureConfig.without_signature_verification()
        ),
    ) as archive:
        # Extract all files using the String output version
        for name in archive.keys():
            archive.write_entry_to(name, os.path.join(tmpdir, name.to_pathbuf()))
    # Check the files

    for name, data in FILES.items():
        with open(os.path.join(tmpdir, name.to_pathbuf()), "rb") as f:
            assert f.read() == data


def test_write_entry_to_file(basic_archive: str) -> None:
    """Test archive.write_entry_to(), using the File output version"""
    # Temporary directory for extraction
    tmpdir = tempfile.mkdtemp()
    with MLAReader(
        basic_archive,
        mla.ReaderConfig.without_encryption(
            mla.SignatureConfig.without_signature_verification()
        ),
    ) as archive:
        # Extract all files using the File output version
        for name in archive.keys():
            with open(os.path.join(tmpdir, name.to_pathbuf()), "wb") as f:
                archive.write_entry_to(name, f)

    # Check the files
    for name, data in FILES.items():
        with open(os.path.join(tmpdir, name.to_pathbuf()), "rb") as f:
            assert f.read() == data


class BytesIOCounter(io.BytesIO):
    """
    Extend BytesIO to count the number of calls to `write` and `read`
    """

    write_count: int
    read_count: int

    def __init__(self, initial_bytes: bytes = b"") -> None:
        super().__init__(initial_bytes)
        self.write_count = 0
        self.read_count = 0

    def write(self, b: Any) -> int:
        self.write_count += 1
        return super().write(b)

    def read(self, size: int | None = None) -> bytes:
        self.read_count += 1
        return super().read(size)


def test_write_entry_to_file_chunk_size(basic_archive):
    """Test archive.write_entry_to(), using the File output version"""
    with MLAReader(
        basic_archive,
        mla.ReaderConfig.without_encryption(
            mla.SignatureConfig.without_signature_verification()
        ),
    ) as archive:
        # Chunk size set to 1 -> expect 5 calls
        output = BytesIOCounter()
        archive.write_entry_to(EntryName("file1"), output, chunk_size=1)

        # Check the number of calls
        assert output.write_count == len(FILES[EntryName("file1")])
        output.seek(0)
        assert output.read() == FILES[EntryName("file1")]

        # Chunk size set to 2 -> expect 3 calls
        output = BytesIOCounter()
        archive.write_entry_to(EntryName("file1"), output, chunk_size=2)

        # Check the number of calls
        assert output.write_count == len(FILES[EntryName("file1")]) // 2 + 1
        output.seek(0)
        assert output.read() == FILES[EntryName("file1")]


def test_add_entry_from_str() -> None:
    "Test archive.add_entry_from(), using the String input version"
    path: str = tempfile.mkstemp(suffix=".mla")[1]

    # Create the archive
    with MLAWriter(
        path, mla.WriterConfig.without_encryption_without_signature()
    ) as archive:
        for name, data in FILES.items():
            # Create a file on disk to import
            fname = tempfile.mkstemp()[1]
            with open(fname, "wb") as f:
                f.write(data)
            # Import the file
            archive.add_entry_from(name, fname)

    # Read the archive
    with MLAReader(
        path,
        mla.ReaderConfig.without_encryption(
            mla.SignatureConfig.without_signature_verification()
        ),
    ) as archive:
        # Compare string representations of keys instead of EntryName objects,
        # because EntryName instances don't support direct comparison
        assert sorted(
            name.raw_content_to_escaped_string() for name in archive.keys()
        ) == sorted(name.raw_content_to_escaped_string() for name in FILES.keys())
        for name, data in FILES.items():
            assert archive[name] == data


def test_add_entry_from_io() -> None:
    "Test archive.add_entry_from(), using the IO input version"
    path: str = tempfile.mkstemp(suffix=".mla")[1]

    # Create the archive
    with MLAWriter(
        path, mla.WriterConfig.without_encryption_without_signature()
    ) as archive:
        for name, data in FILES.items():
            # Use a buffered IO
            f = io.BytesIO(data)
            # Import the data
            archive.add_entry_from(name, f)

    # Read the archive
    with MLAReader(
        path,
        mla.ReaderConfig.without_encryption(
            mla.SignatureConfig.without_signature_verification()
        ),
    ) as archive:
        # Compare string representations of keys instead of EntryName objects,
        # because EntryName instances don't support direct comparison
        assert sorted(
            name.raw_content_to_escaped_string() for name in archive.keys()
        ) == sorted(name.raw_content_to_escaped_string() for name in FILES.keys())
        for name, data in FILES.items():
            assert archive[name] == data


def test_add_entry_from_io_chunk_size() -> None:
    "Test archive.add_entry_from(), using the IO input version"
    for chunk_size in [1, 2]:
        path: str = tempfile.mkstemp(suffix=".mla")[1]
        data: bytes = FILES[EntryName("file1")]

        # Create the archive
        with MLAWriter(
            path, mla.WriterConfig.without_encryption_without_signature()
        ) as archive:
            src = BytesIOCounter(data)
            archive.add_entry_from(EntryName("file1"), src, chunk_size=chunk_size)

            # Check the number of calls
            if chunk_size == 1:
                # Chunk size set to 1 -> expect 6 calls (5 with data, 1 empty)
                assert src.read_count == len(data) + 1
            elif chunk_size == 2:
                # Chunk size set to 2 -> expect 4 calls (3 with data, 1 empty)
                assert src.read_count == 4

        # Read the archive
        with MLAReader(
            path,
            mla.ReaderConfig.without_encryption(
                mla.SignatureConfig.without_signature_verification()
            ),
        ) as archive:
            assert archive[EntryName("file1")] == data
