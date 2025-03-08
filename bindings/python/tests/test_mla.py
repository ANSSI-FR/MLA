import hashlib
import pytest
import tempfile
import os
import io

import mla
from mla import MLAFile, MLAError

# Test data
FILES = {
    "file1": b"DATA1",
    "file2": b"DATA_2",
}

@pytest.fixture
def basic_archive():
    "Create a temporary archive and return its path"
    fname = tempfile.mkstemp(suffix=".mla")[1]
    archive = MLAFile(fname, "w")
    for name, data in FILES.items():
        archive[name] = data
    archive.finalize()
    return fname

def test_layers_bitflag_export():
    assert mla.LAYER_DEFAULT == mla.LAYER_COMPRESS | mla.LAYER_ENCRYPT
    assert mla.LAYER_EMPTY == 0
    assert mla.LAYER_DEFAULT != mla.LAYER_EMPTY

def test_bad_mode():
    "Ensure MLAFile with an unknown mode raise an error"
    target_file = "/tmp/must_not_exists"
    with pytest.raises(mla.BadAPIArgument):
        MLAFile(target_file, "x")
    # Ensure the file has not been created
    with pytest.raises(FileNotFoundError):
        open(target_file)

def test_repr():
    "Ensure the repr is correct"
    path = tempfile.mkstemp(suffix=".mla")[1]
    archive = MLAFile(path, "w")
    assert repr(archive) == "<MLAFile path='%s' mode='w'>" % path
    archive.finalize()

def test_forbidden_in_write_mode():
    "Ensure some API cannot be called in write mode"
    archive = MLAFile(tempfile.mkstemp(suffix=".mla")[1], "w")

    # .keys
    with pytest.raises(mla.BadAPIArgument):
        archive.keys()
    
    # __contains__
    with pytest.raises(mla.BadAPIArgument):
        "name" in archive
    
    # __getitem__
    with pytest.raises(mla.BadAPIArgument):
        archive["name"]
    
    # __len__
    with pytest.raises(mla.BadAPIArgument):
        len(archive)

    # list_files
    with pytest.raises(mla.BadAPIArgument):
        archive.list_files()

def test_forbidden_in_read_mode(basic_archive):
    "Ensure some API cannot be called in write mode"
    archive = MLAFile(basic_archive)

    # __setitem__
    with pytest.raises(mla.BadAPIArgument):
        archive["file"] = b"data"

    # .finalize
    with pytest.raises(mla.BadAPIArgument):
        archive.finalize()

def test_read_api(basic_archive):
    "Test basics read APIs"
    archive = MLAFile(basic_archive)

    # .keys
    assert sorted(archive.keys()) == sorted(list(FILES.keys()))

    # __contains__
    assert "file1" in archive
    assert "file3" not in archive

    # __getitem__
    assert archive["file1"] == FILES["file1"]
    assert archive["file2"] == FILES["file2"]
    with pytest.raises(KeyError):
        archive["file3"]

    # __len__
    assert len(archive) == 2

def test_list_files(basic_archive):
    "Test list files possibilities"
    archive = MLAFile(basic_archive)

    # Basic
    assert sorted(archive.list_files()) == sorted(list(FILES.keys()))

    # With size
    assert sorted([
        (filename, info.size) for filename, info in archive.list_files(include_size=True).items()
    ]) == sorted([
        (filename, len(data)) for filename, data in FILES.items()
    ])

    # With hash
    assert sorted([
        (filename, info.hash) for filename, info in archive.list_files(include_hash=True).items()
    ]) == sorted([
        (filename, hashlib.sha256(data).digest()) for filename, data in FILES.items()
    ])

    # With size and hash
    assert sorted([
        (filename, info.size, info.hash) for filename, info in archive.list_files(include_size=True, include_hash=True).items()
    ]) == sorted([
        (filename, len(data), hashlib.sha256(data).digest()) for filename, data in FILES.items()
    ])

def test_write_api():
    "Test basics write APIs"
    path = tempfile.mkstemp(suffix=".mla")[1]
    archive = MLAFile(path, "w")

    # __setitem__
    for name, data in FILES.items():
        archive[name] = data

    # close
    archive.finalize()

    # Check the resulting archive
    archive = MLAFile(path)
    assert sorted(archive.keys()) == sorted(list(FILES.keys()))
    assert archive["file1"] == FILES["file1"]
    assert archive["file2"] == FILES["file2"]

def test_double_write():
    "Rewriting the file must raise an MLA error"
    archive = MLAFile(tempfile.mkstemp(suffix=".mla")[1], "w")
    archive["file1"] = FILES["file1"]
    
    with pytest.raises(mla.DuplicateFilename):
        archive["file1"] = FILES["file1"]

def test_context_read(basic_archive):
    "Test reading using a `with` statement (context management protocol)"
    with MLAFile(basic_archive) as mla:
        assert sorted(mla.keys()) == sorted(list(FILES.keys()))
        for name, data in FILES.items():
            assert mla[name] == data

def test_context_write():
    "Test writing using a `with` statement (context management protocol)"
    path = tempfile.mkstemp(suffix=".mla")[1]
    with MLAFile(path, "w") as mla:
        for name, data in FILES.items():
            mla[name] = data
    
    # Check the resulting file
    with MLAFile(path) as mla:
        assert sorted(mla.keys()) == sorted(list(FILES.keys()))
        for name, data in FILES.items():
            assert mla[name] == data

def test_context_write_error():
    "Raise an error during the context write __exit__"
    with pytest.raises(mla.WrongArchiveWriterState):
        with MLAFile(tempfile.mkstemp(suffix=".mla")[1], "w") as archive:
            # INTENTIONNALY BUGGY
            # .finalize will be called twice, causing an exception
            archive.finalize()

def test_context_write_error_in_with():
    "Raise an error in the with statement, it must be re-raised"
    CustomException = type("CustomException", (Exception,), {})
    with pytest.raises(CustomException):
        with MLAFile(tempfile.mkstemp(suffix=".mla")[1], "w") as mla:
            # INTENTIONNALY BUGGY
            raise CustomException

def test_writer_config_layers():
    "Test writer config creation for layers"
    # Enable and disable layers
    config = mla.WriterConfig()
    assert config.layers == mla.LAYER_DEFAULT

    config = mla.WriterConfig(layers=mla.LAYER_COMPRESS)
    assert config.layers == mla.LAYER_COMPRESS

    config.enable_layer(mla.LAYER_ENCRYPT)
    assert config.layers == mla.LAYER_COMPRESS | mla.LAYER_ENCRYPT

    config.disable_layer(mla.LAYER_COMPRESS)
    assert config.layers == mla.LAYER_ENCRYPT

    config.disable_layer(mla.LAYER_ENCRYPT)
    assert config.layers == mla.LAYER_EMPTY

    # Check for error on unknown layer (0xFF)
    with pytest.raises(mla.BadAPIArgument):
        config.enable_layer(0xFF)
    
    with pytest.raises(mla.BadAPIArgument):
        config.disable_layer(0xFF)
    
    with pytest.raises(mla.BadAPIArgument):
        config.set_layers(0xFF)
    
    with pytest.raises(mla.BadAPIArgument):
        config = mla.WriterConfig(layers=0xFF)
    
    # Chaining
    config = mla.WriterConfig().enable_layer(
            mla.LAYER_COMPRESS
        ).enable_layer(
            mla.LAYER_ENCRYPT
        ).disable_layer(
            mla.LAYER_COMPRESS
        ).set_layers(
            mla.LAYER_COMPRESS
        )
    assert config.layers == mla.LAYER_COMPRESS

def test_writer_config_compression():
    "Test compression API in WriterConfig creation"
    config = mla.WriterConfig()
    with pytest.raises(OverflowError):
        config.with_compression_level(-1)
    with pytest.raises(mla.ConfigError):
        config.with_compression_level(0xFF)
    
    # Value
    config.with_compression_level(mla.DEFAULT_COMPRESSION_LEVEL)
    assert config.compression_level == mla.DEFAULT_COMPRESSION_LEVEL
    config.with_compression_level(1)
    assert config.compression_level == 1

    # Chaining
    out = config.with_compression_level(mla.DEFAULT_COMPRESSION_LEVEL)
    assert out is config

# Expected: mla/bindings/python/tests/
MLA_BASE_PATH = os.path.dirname(
    os.path.dirname(
        os.path.dirname(
            os.path.dirname(
                __file__
            )
        )
    )
)
SAMPLE_PATH = os.path.join(MLA_BASE_PATH, "samples")

def test_public_keys():
    "Test the PublicKeys object"
    # Bad parsing
    with pytest.raises(mla.InvalidKeyFormat):
        mla.PublicKeys(b"NOT A KEY")
    
    with pytest.raises(FileNotFoundError):
        mla.PublicKeys("/tmp/does_not_exists")
    
    # Open a PEM key, through path
    pkeys_pem = mla.PublicKeys(os.path.join(SAMPLE_PATH, "test_mlakey_pub.pem"))
    assert len(pkeys_pem.keys) == 1
    
    # Open a DER key, through path
    pkeys_der = mla.PublicKeys(os.path.join(SAMPLE_PATH, "test_mlakey_pub.der"))
    assert len(pkeys_pem.keys) == 1

    # Keys must be the same
    assert pkeys_pem.keys == pkeys_der.keys

    # Open a PEM key, through data
    pkeys_pem = mla.PublicKeys(open(os.path.join(SAMPLE_PATH, "test_mlakey_pub.pem"), "rb").read())
    assert len(pkeys_pem.keys) == 1
    
    # Open a DER key, through data
    pkeys_pem = mla.PublicKeys(open(os.path.join(SAMPLE_PATH, "test_mlakey_pub.der"), "rb").read())
    assert len(pkeys_pem.keys) == 1
    
    # Keys must be the same
    assert pkeys_pem.keys == pkeys_der.keys

    # Open several keys, using both path and data
    pkeys =  mla.PublicKeys(
        os.path.join(SAMPLE_PATH, "test_mlakey_pub.pem"),
        open(os.path.join(SAMPLE_PATH, "test_mlakey_2_pub.pem"), "rb").read()
    )
    assert len(pkeys.keys) == 2

def test_private_keys():
    "Test the PrivateKeys object"
    # Bad parsing
    with pytest.raises(mla.InvalidKeyFormat):
        mla.PrivateKeys(b"NOT A KEY")
    
    with pytest.raises(mla.InvalidKeyFormat):
        # This is a public key, not a private one
        mla.PrivateKeys(os.path.join(SAMPLE_PATH, "test_mlakey_pub.pem"))

    with pytest.raises(FileNotFoundError):
        mla.PrivateKeys("/tmp/does_not_exists")
    
    # Open a PEM key, through path
    pkeys_pem = mla.PrivateKeys(os.path.join(SAMPLE_PATH, "test_mlakey.pem"))
    assert len(pkeys_pem.keys) == 1
    
    # Open a DER key, through path
    pkeys_der = mla.PrivateKeys(os.path.join(SAMPLE_PATH, "test_mlakey.der"))
    assert len(pkeys_pem.keys) == 1

    # Keys must be the same
    assert pkeys_pem.keys == pkeys_der.keys

    # Open a PEM key, through data
    pkeys_pem = mla.PrivateKeys(open(os.path.join(SAMPLE_PATH, "test_mlakey.pem"), "rb").read())
    assert len(pkeys_pem.keys) == 1
    
    # Open a DER key, through data
    pkeys_pem = mla.PrivateKeys(open(os.path.join(SAMPLE_PATH, "test_mlakey.der"), "rb").read())
    assert len(pkeys_pem.keys) == 1
    
    # Keys must be the same
    assert pkeys_pem.keys == pkeys_der.keys

    # Open several keys, using both path and data
    pkeys =  mla.PrivateKeys(
        os.path.join(SAMPLE_PATH, "test_mlakey.pem"),
        open(os.path.join(SAMPLE_PATH, "test_mlakey_2.pem"), "rb").read()
    )
    assert len(pkeys.keys) == 2

def test_writer_config_public_keys():
    "Test public keys API in WriterConfig creation"

    # Test API call
    config = mla.WriterConfig()
    with pytest.raises(mla.InvalidKeyFormat):
        config.set_public_keys(mla.PublicKeys(b"NOT A KEY"))
    
    # Test shortcut on object build
    config = mla.WriterConfig(
        public_keys=mla.PublicKeys(os.path.join(SAMPLE_PATH, "test_mlakey_pub.pem"))
    )
    # Test the getter
    assert len(config.public_keys.keys) == 1

    # Chaining
    out = config.set_public_keys(mla.PublicKeys(
        os.path.join(SAMPLE_PATH, "test_mlakey_pub.pem"),
        open(os.path.join(SAMPLE_PATH, "test_mlakey_2_pub.pem"), "rb").read()
    ))
    assert out is config
    assert len(config.public_keys.keys) == 2

def test_mlafile_bad_config():
    "Try to create a MLAFile with the wrong config parameter"
    with pytest.raises(TypeError):
        MLAFile(tempfile.mkstemp(suffix=".mla")[1], "w", config="NOT A CONFIG")
    
    with pytest.raises(TypeError):
        MLAFile(tempfile.mkstemp(suffix=".mla")[1], "w", config=mla.ReaderConfig())
    
    with pytest.raises(TypeError):
        MLAFile(tempfile.mkstemp(suffix=".mla")[1], "r", config=mla.WriterConfig())
    

def test_reader_config_api():
    "Test the ReaderConfig API"
    # Add a remove private keys
    config = mla.ReaderConfig()
    assert config.private_keys is None

    config.set_private_keys(
        mla.PrivateKeys(os.path.join(SAMPLE_PATH, "test_mlakey.pem"))
    )
    assert len(config.private_keys.keys) == 1

    config = mla.ReaderConfig(private_keys=mla.PrivateKeys(os.path.join(SAMPLE_PATH, "test_mlakey.pem")))
    assert len(config.private_keys.keys) == 1

    # Chaining
    config = mla.ReaderConfig()
    out = config.set_private_keys(
        mla.PrivateKeys(os.path.join(SAMPLE_PATH, "test_mlakey.pem")),
    )
    assert out is config

def test_write_then_read_encrypted():
    "Create an encrypted archive, then read it"
    # Create the archive
    path = tempfile.mkstemp(suffix=".mla")[1]
    with MLAFile(path, "w", config=mla.WriterConfig(
        public_keys=mla.PublicKeys(os.path.join(SAMPLE_PATH, "test_mlakey_pub.pem")),
        layers=mla.LAYER_ENCRYPT
    )) as archive:
        for name, data in FILES.items():
            archive[name] = data
    
    # Read the archive
    with MLAFile(path, config=mla.ReaderConfig(
        private_keys=mla.PrivateKeys(os.path.join(SAMPLE_PATH, "test_mlakey.pem"))
    )) as archive:
        assert sorted(archive.keys()) == sorted(list(FILES.keys()))
        for name, data in FILES.items():
            assert archive[name] == data

def test_read_encrypted_archive_bad_key():
    "Try to read an encrypted archive with a bad key"
    # Create the archive
    path = tempfile.mkstemp(suffix=".mla")[1]
    with MLAFile(path, "w", config=mla.WriterConfig(
        public_keys=mla.PublicKeys(os.path.join(SAMPLE_PATH, "test_mlakey_pub.pem")),
        layers=mla.LAYER_ENCRYPT
    )) as archive:
        for name, data in FILES.items():
            archive[name] = data

    # Try to read without a key
    with pytest.raises(mla.PrivateKeyNeeded):
        with MLAFile(path) as archive:
            pass
    
    # Try to read with an incorrect key (mla.ConfigError: PrivateKeyNotFound)
    with pytest.raises(mla.ConfigError):
        with MLAFile(path, config=mla.ReaderConfig(
            private_keys=mla.PrivateKeys(os.path.join(SAMPLE_PATH, "test_mlakey_2.pem"))
        )) as archive:
            pass

def test_write_file_to_str(basic_archive):
    """Test archive.write_file_to(), using the String output version"""
    # Temporary directory for extraction
    tmpdir = tempfile.mkdtemp()
    with MLAFile(basic_archive) as archive:
        # Extract all files using the String output version
        for name in archive.keys():
            archive.write_file_to(name, os.path.join(tmpdir, name))

    # Check the files
    for name, data in FILES.items():
        assert open(os.path.join(tmpdir, name), "rb").read() == data

def test_write_file_to_file(basic_archive):
    """Test archive.write_file_to(), using the File output version"""
    # Temporary directory for extraction
    tmpdir = tempfile.mkdtemp()
    with MLAFile(basic_archive) as archive:
        # Extract all files using the File output version
        for name in archive.keys():
            with open(os.path.join(tmpdir, name), "wb") as f:
                archive.write_file_to(name, f)

    # Check the files
    for name, data in FILES.items():
        assert open(os.path.join(tmpdir, name), "rb").read() == data


class BytesIOCounter(io.BytesIO):
    """
    Extend BytesIO to count the number of calls to `write` and `read`
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.write_count = 0
        self.read_count = 0
    
    def write(self, *args, **kwargs):
        self.write_count += 1
        return super().write(*args, **kwargs)
    
    def read(self, *args, **kwargs):
        self.read_count += 1
        return super().read(*args, **kwargs)


def test_write_file_to_file_chunk_size(basic_archive):
    """Test archive.write_file_to(), using the File output version"""
    with MLAFile(basic_archive) as archive:
        # Chunk size set to 1 -> expect 5 calls
        output = BytesIOCounter()
        archive.write_file_to("file1", output, chunk_size=1)

        # Check the number of calls
        assert output.write_count == len(FILES["file1"])
        output.seek(0)
        assert output.read() == FILES["file1"]

        # Chunk size set to 2 -> expect 3 calls
        output = BytesIOCounter()
        archive.write_file_to("file1", output, chunk_size=2)

        # Check the number of calls
        assert output.write_count == len(FILES["file1"]) // 2 + 1
        output.seek(0)
        assert output.read() == FILES["file1"]

def test_add_file_from_str():
    "Test archive.add_file_from(), using the String input version"
    # Create the archive
    path = tempfile.mkstemp(suffix=".mla")[1]
    with MLAFile(path, "w") as archive:
        for name, data in FILES.items():
            # Create a file on disk to import
            fname = tempfile.mkstemp()[1]
            with open(fname, "wb") as f:
                f.write(data)
            # Import the file
            archive.add_file_from(name, fname)

    # Read the archive
    with MLAFile(path) as archive:
        assert sorted(archive.keys()) == sorted(list(FILES.keys()))
        for name, data in FILES.items():
            assert archive[name] == data

def test_add_file_from_io():
    "Test archive.add_file_from(), using the IO input version"
    # Create the archive
    path = tempfile.mkstemp(suffix=".mla")[1]
    with MLAFile(path, "w") as archive:
        for name, data in FILES.items():
            # Use a buffered IO
            f = io.BytesIO(data)
            # Import the data
            archive.add_file_from(name, f)

    # Read the archive
    with MLAFile(path) as archive:
        assert sorted(archive.keys()) == sorted(list(FILES.keys()))
        for name, data in FILES.items():
            assert archive[name] == data

def test_add_file_from_io_chunk_size():
    "Test archive.add_file_from(), using the IO input version"
    for chunk_size in [1, 2]:    
        # Create the archive
        path = tempfile.mkstemp(suffix=".mla")[1]
        data = FILES["file1"]
        with MLAFile(path, "w") as archive:
            src = BytesIOCounter(data)
            archive.add_file_from("file1", src, chunk_size=chunk_size)

            # Check the number of calls
            if chunk_size == 1:
                # Chunk size set to 1 -> expect 6 calls (5 with data, 1 empty)
                assert src.read_count == len(data) + 1
            elif chunk_size == 2:
                # Chunk size set to 2 -> expect 4 calls (3 with data, 1 empty)
                assert src.read_count == 4

        # Read the archive
        with MLAFile(path) as archive:
            assert archive["file1"] == data

    