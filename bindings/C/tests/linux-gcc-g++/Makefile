CFLAGS ?= -Wall -Wextra -pedantic -Werror -Wno-overlength-strings -O0 -g -I../../
LDFLAGS ?= -O1 -lpthread -ldl -lm
BUILDDIR ?= ../../../../target
TARGET ?= x86_64-unknown-linux-gnu
MLAR ?= $(BUILDDIR)/$(TARGET)/debug/mlar

tests: test_create test_create_manykeys test_create_set_compression_level test_create_set_compression_level_fail_invalid test_create_interleaved test_create_no_early_close test_create_unicode test_create_stream test_create_write_byte_by_byte test_open test_info

test_create: $(MLAR) create.elf
	./create.elf
	$(MLAR) cat test.txt --skip-signature-verification --input ./test.mla -k ../../../../samples/test_mlakey.mlapriv | grep -E '^Hello, World!$$'

test_create_manykeys: $(MLAR) create_manykeys.elf
	./create_manykeys.elf
	$(MLAR) cat --skip-signature-verification test.txt --input ./test.mla -k ../../../../samples/test_mlakey.mlapriv | grep -E '^Hello, World!$$'

test_create_set_compression_level: $(MLAR) create_set_compression_level.elf
	./create_set_compression_level.elf

test_create_set_compression_level_fail_invalid: $(MLAR) create_set_compression_level_fail_invalid.elf
	./create_set_compression_level_fail_invalid.elf

test_create_interleaved: $(MLAR) create_interleaved.elf
	./create_interleaved.elf
	$(MLAR) cat test1.txt --skip-signature-verification --input ./test.mla -k ../../../../samples/test_mlakey.mlapriv | grep -E '^Hello, World!$$'
	$(MLAR) cat test2.txt --skip-signature-verification --input ./test.mla -k ../../../../samples/test_mlakey.mlapriv | grep -E '^Hello, World!$$'

test_create_no_early_close: $(MLAR) create_no_early_close.elf
	./create_no_early_close.elf

test_create_unicode: $(MLAR) create_unicode.elf
	./create_unicode.elf
	$(MLAR) cat $(shell printf 'test\xE2\x98\xA0.txt') --skip-signature-verification --input ./test.mla -k ../../../../samples/test_mlakey.mlapriv | grep -E '^Hello, World!$$'

test_create_stream: $(MLAR) create_stream.elf
	yes "All work and no play makes Jack a dull boy" | dd bs=1M count=2 iflag=fullblock | ./create_stream.elf
	bash -c "$(MLAR) cat test.txt --skip-signature-verification --input ./test.mla -k ../../../../samples/test_mlakey.mlapriv | sha256sum -c <(echo \"132f5f1a403697b63eec77930cb1ab38414c82ca4c7d415d8dc6e3d3eb6a8b98 -\")"
	yes "All work and no play makes Jack a dull boy" | dd bs=1M count=20 iflag=fullblock | ./create_stream.elf
	bash -c "$(MLAR) cat test.txt --skip-signature-verification --input ./test.mla -k ../../../../samples/test_mlakey.mlapriv | sha256sum -c <(echo \"e667ca14e52cbea16f6e0413e5fdfb7e789a3f1af80c2a795c36e2523195a20d -\")"

test_create_write_byte_by_byte: $(MLAR) create_write_byte_by_byte.elf
	./create_write_byte_by_byte.elf
	$(MLAR) cat test.txt --skip-signature-verification --input ./test.mla -k ../../../../samples/test_mlakey.mlapriv | grep -E '^Hello, World!$$'

test_open: $(MLAR) open.elf
	./open.elf
	bash -c "cd extracted; sha256sum --quiet -c sha256sum"

test_info: $(MLAR) info.elf
	./info.elf

%.expanded.c: %.c
	sh -c 'k=`tr -d "\r" <../../../../samples/test_mlakey.mlapub|tr "\n" "!"|sed "s#!#\\\\\\\\\\\\\\\\r\\\\\\\\\\\\\\\\n#g"`; sed -e "s#REPLACE WITH PUBLIC KEY FROM SAMPLE#$$k#"' < $< > /tmp/a
	sh -c 'k=`tr -d "\r" <../../../../samples/test_mlakey_2.mlapub|tr "\n" "!"|sed "s#!#\\\\\\\\\\\\\\\\r\\\\\\\\\\\\\\\\n#g"`; sed -e "s#REPLACE WITH PUBLIC KEY 2 FROM SAMPLE#$$k#"' < /tmp/a > /tmp/b
	sh -c 'k=`tr -d "\r" <../../../../samples/test_mlakey_archive_v2_receiver.mlapriv|tr "\n" "!"|sed "s#!#\\\\\\\\\\\\\\\\r\\\\\\\\\\\\\\\\n#g"`; sed -e "s#REPLACE WITH PRIVATE ARCHIVE V2 RECEIVER PRIVATE KEY FROM SAMPLE#$$k#"' < /tmp/b > /tmp/c
	sh -c 'k=`tr -d "\r" <../../../../samples/test_mlakey_archive_v2_sender.mlapub|tr "\n" "!"|sed "s#!#\\\\\\\\\\\\\\\\r\\\\\\\\\\\\\\\\n#g"`; sed -e "s#REPLACE WITH PRIVATE ARCHIVE V2 SENDER PUBLIC KEY FROM SAMPLE#$$k#"' < /tmp/c > $@

%.elf: %.expanded.c $(BUILDDIR)/$(TARGET)/debug/libmla.a
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(MLAR): FORCE
	cargo build --target=$(TARGET) --manifest-path=../../../../mlar/Cargo.toml

$(BUILDDIR)/$(TARGET)/debug/libmla.a: FORCE
	cargo build --target=$(TARGET)

FORCE:

clean:
	rm *.elf; rm *.expanded.c; rm -rf ./extracted; rm ./test.mla
