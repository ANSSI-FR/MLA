import hashlib
import pytest
import tempfile
import os

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
    assert config.layers == mla.LAYER_EMPTY

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
    with pytest.raises(mla.InvalidECCKeyFormat):
        mla.PublicKeys(b"NOT A KEY")
    
    with pytest.raises(FileNotFoundError):
        mla.PublicKeys("/tmp/does_not_exists")
    
    # Open a PEM key, through path
    pkeys_pem = mla.PublicKeys(os.path.join(SAMPLE_PATH, "test_ed25519_pub.pem"))
    assert len(pkeys_pem.keys) == 1
    
    # Open a DER key, through path
    pkeys_der = mla.PublicKeys(os.path.join(SAMPLE_PATH, "test_ed25519_pub.der"))
    assert len(pkeys_pem.keys) == 1

    # Keys must be the same
    assert pkeys_pem.keys == pkeys_der.keys

    # Open a PEM key, through data
    pkeys_pem = mla.PublicKeys(open(os.path.join(SAMPLE_PATH, "test_ed25519_pub.pem"), "rb").read())
    assert len(pkeys_pem.keys) == 1
    
    # Open a DER key, through data
    pkeys_pem = mla.PublicKeys(open(os.path.join(SAMPLE_PATH, "test_ed25519_pub.der"), "rb").read())
    assert len(pkeys_pem.keys) == 1
    
    # Keys must be the same
    assert pkeys_pem.keys == pkeys_der.keys

    # Open several keys, using both path and data
    pkeys =  mla.PublicKeys(
        os.path.join(SAMPLE_PATH, "test_ed25519_pub.pem"),
        open(os.path.join(SAMPLE_PATH, "test_x25519_2_pub.pem"), "rb").read()
    )
    assert len(pkeys.keys) == 2