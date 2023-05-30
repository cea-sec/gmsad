import logging
import time
import struct
from typing import Optional, Any, Tuple, BinaryIO, List
import io

from gmsad.enctypes import ENCTYPES, MS_ENCTYPES_TO_RFC

KEYTAB_FILE_FORMAT_MAGIC = 0x502

class EmptyKeytabEntry(Exception):
    """ The keytab entry is empty """

    def __init__(self, size: int, *args: Any) -> None:
        super().__init__(args)
        self.size = size

    def __str__(self) -> str:
        return f"The keytab entry is invalid (size = {self.size})"


class EndOfKeytabEntries(Exception):
    """ This is the end of keytab entries list """


class InvalidPrincipal(Exception):
    """ The principal syntax is invalid """


def unpack(format: str, fd: BinaryIO, offset: int = 0) -> Tuple[Any, int]:
    """
    Unpack from the stream <fd> according to the format string
    <format>.
    :returns: (value, offset), where <value> is the unpacked value
        and <offset> the number of bytes read added to the
        <offset> argument if defined).
        Contrary to struct.unpack, this function does not return
        a Tuple if the return value is only one element.
    """
    s = struct.Struct(format)
    res = s.unpack(fd.read(s.size))
    offset += s.size
    if len(res) == 1:
        return res[0], offset
    return res, offset


def pack(format: str, fd: BinaryIO, value: Any) -> int:
    """
    Pack the value <value> according to the format string
    <format> and write it to the stream <fd>.
    :returns: the number of bytes written.
    """
    s = struct.Struct(format)
    fd.write(s.pack(value))
    return s.size


def unpack_counted_octet_string(fd: BinaryIO, offset: int = 0) -> Tuple[bytes, int]:
    """
    Unpack a `counted_octet_string` from the stream <fd>, which is
    a "length + value" struct.
    :returns: (value, offset), where <value> contains the value bytes
        and offset the number of bytes read (added to <offset> argument
        if defined)
    """
    length, offset = unpack('!H', fd, offset)
    string = fd.read(length)
    offset += length
    return string, offset


def pack_counted_octet_string(fd: BinaryIO, value: bytes) -> int:
    """
    Pack a `counted_octet_string` and write it to the stream <fd>.
    :returns: the number of bytes written
    """
    count = pack('!H', fd, len(value))
    fd.write(value)
    count += len(value)
    return count


class Keyblock:
    type: int
    key: bytes

    def __init__(self, type: int, key: bytes) -> None:
        self.type = type
        self.key = key

    @staticmethod
    def from_stream(fd: BinaryIO) -> Tuple['Keyblock', int]:
        """
        Unserialize a Keyblock from the stream <fd>
        :return:the number of bytes read
        """
        offset = 0
        _type, offset = unpack('!H', fd, offset)
        # TODO: validate type

        key, offset = unpack_counted_octet_string(fd, offset)
        return (Keyblock(_type, key), offset)

    def to_stream(self, fd: BinaryIO) -> int:
        """
        Serialize a Keyblock to the stream <fd>
        :return: the number of bytes written
        """
        count = pack('!H', fd, self.type)
        count += pack_counted_octet_string(fd, self.key)
        return count

    def __repr__(self) -> str:
        return f"Keyblock {{type: {self.type}, key: {list(self.key)}}}"


class KeytabEntry:
    realm: str
    components: List[str]
    name_type: int
    timestamp: int
    vno: int
    key: Keyblock

    def __init__(self, princ: str, kvno: int, timestamp: int, key: Keyblock):
        self.principal = princ
        # Always use KRB5_NT_PRINCIPAL
        self.name_type = 1
        self.timestamp = timestamp
        self.vno = kvno
        self.key = key

    @staticmethod
    def from_stream(fd: BinaryIO) -> Tuple['KeytabEntry', int]:
        """
        Unserialize keytab entry from fd and populates
        the current class instance with values stored in keytab.
        :param fd: the IO stream to read from
        :returns: the number of bytes read
        """
        try:
            # Size indicates the number of bytes that follow in the entry
            size, _ = unpack('!i', fd)
        except struct.error:
            raise EndOfKeytabEntries()

        if size < 0:
            raise EmptyKeytabEntry(size)

        # There are <size> bytes following in the entry
        # offset will be used to know where we are
        offset = 0
        num_components, offset = unpack('!H', fd, offset)
        realm_raw, offset = unpack_counted_octet_string(fd, offset)

        # For the realm and name components, the counted_octet_string bytes
        # are ASCII encoded text with no zero terminator
        realm = realm_raw.decode('ascii')
        components = []
        for _ in range(num_components):
            component, offset = unpack_counted_octet_string(fd, offset)
            components.append(component.decode('ascii'))

        name_type, offset = unpack('!I', fd, offset)
        # TODO: validate type

        timestamp, offset = unpack('!I', fd, offset)
        vno, offset = unpack('!B', fd, offset)

        key, count = Keyblock.from_stream(fd)
        offset += count

        # Overwrite 8-bit vno if vno field is defined, i.e. if there
        # at least 4 bytes remaining to read
        # TODO: check <= or <
        if offset + 4 <= size:
            vno, offset = unpack('!I', fd, offset)

        if offset != size:
            logging.warning("Strange keytab entry: stored size (%d) is "
                            "greater than real size (%d)", size, offset)
            # Read missing bytes
            fd.read(size - offset)

        princ = '/'.join(components) + '@' + realm
        entry = KeytabEntry(princ, vno, timestamp, key)

        # Total read size is the size of the "size" field (!i) added to its value
        return (entry, struct.calcsize('!i') + size)

    def to_stream(self, fd: BinaryIO) -> int:
        """
        Serialize the keytab entry and writes it into fd.
        :return the number of bytes written
        """
        # Compute size using an in-memory stream
        out = io.BytesIO()
        count = pack('!H', out, len(self.components))

        count += pack_counted_octet_string(out, self.realm.encode('ascii'))
        for component in self.components:
            count += pack_counted_octet_string(out, component.encode('ascii'))

        count += pack('!I', out, self.name_type)
        count += pack('!I', out, self.timestamp)

        count += pack('!B', out, self.vno if self.vno <= 0xff else self.vno % 0xff)
        count += self.key.to_stream(out)

        if self.vno > 0xff:
            count += pack('!I', out, self.vno)

        assert count == len(out.getvalue())

        pack('!i', fd, count)
        fd.write(out.getvalue())

        return struct.calcsize('!i') + count

    def __repr__(self) -> str:
        res = f"KeytabEntry {{\n" \
              f"\trealm: {self.realm}\n" \
              f"\tcomponents: \n"
        for component in self.components:
            res += f"\t\t- {component}\n"

        res += f"\tname_type: {self.name_type}\n" \
               f"\ttimestamp: {self.timestamp}\n" \
               f"\tvno: {self.vno}\n" \
               f"\tkey: {self.key!r}\n" \
               f"}}\n"
        return res

    @property
    def principal(self) -> str:
        return '/'.join(self.components) + '@' + self.realm

    @principal.setter
    def principal(self, princ: str) -> None:
        if not '@' in princ:
            raise InvalidPrincipal()
        princ, self.realm = princ.split('@')
        self.components = princ.split('/')

class Keytab:
    """
    This class is responsible for dealing with keytab files.
    It can serialize and unserialize the keytab 0x502 format as
    described in
    https://www.gnu.org/software/shishi/manual/html_node/The-Keytab-Binary-File-Format.html
    """
    entries: List[KeytabEntry]

    def __init__(self) -> None:
        self.entries = []

    # TODO: add a __repr__

    def open(self, filename: str) -> None:
        """
        Open a keytab file and store its content in memory
        """
        try:
            with open(filename, 'r+b') as fd:
                self.read(fd)
                logging.debug("%d keytab entries loaded from %s",
                        len(self.entries), filename)
        except FileNotFoundError:
            logging.debug("Keytab file %s does not exist.", filename)

    def read(self, fd: BinaryIO) -> None:
        """
        Parse a keytab file content and add its entries to this
        class instance
        """
        try:
            file_format_version, _ = unpack('!H', fd)
        except struct.error:
            logging.info("Keytab file is empty.")
            return

        assert file_format_version == KEYTAB_FILE_FORMAT_MAGIC

        while True:
            try:
                entry, count = KeytabEntry.from_stream(fd)
            except EmptyKeytabEntry as e:
                logging.debug("Empty keytab entry found with size: %d", e.size)
                # e.size is a negative number
                # According to the Shishi documentation, -e.size is the offset
                # to the next keytab_entry.
                # TODO: Try to find test materials
                fd.seek(-e.size)
            except EndOfKeytabEntries:
                break
            self.entries.append(entry)

    def to_stream(self, fd: BinaryIO) -> None:
        """
        Serialize keytab content into <fd> stream
        """
        offset = pack('!H', fd, KEYTAB_FILE_FORMAT_MAGIC)
        for entry in self.entries:
            entry.to_stream(fd )

    def have_content(self) -> bool:
        """
        Check if the keytab exists and has entries
        :returns: bool
        """
        return len(self.entries) > 0

    def remove_entries(self, princ: str) -> None:
        """
        Remove all entries corresponding to principal <princ>
        in the keytab.
        This change only affects the keytab file on disk if <write>
        is called.
        """
        logging.debug("Remove existing keys for %s of keytab", princ)
        self.entries = [
                entry
                for entry in self.entries
                if entry.principal != princ]

    def add_entry(self, princ: str, salt: str, kvno: int, password: bytes,
            enctypes: int) -> None:
        """
        Add a new entry in the keytab.
        This change only affects the keytab file on disk if <write>
        is called.
        :param princ: principal string
        :param salt: the salt used for keys generation
        :param kvno: the kvno to write
        :param password: the cleartext password as bytes
        :param enctypes: the wanted enctypes (int with Microsoft values)
        """
        for enctype in MS_ENCTYPES_TO_RFC.keys():
            if enctype & enctypes:
                logging.debug("Add entry for princ %s with salt %s "
                              "with etype %d and kvno %d",
                              princ, salt, enctype, kvno)
                enctypes ^= enctype

                string_to_key = ENCTYPES[MS_ENCTYPES_TO_RFC[enctype]]
                keyblock = Keyblock(MS_ENCTYPES_TO_RFC[enctype],
                        string_to_key(password, salt.encode('utf-8')))
                entry = KeytabEntry(princ, kvno, int(time.time()), keyblock)
                self.entries.append(entry)
        if enctypes != 0:
            logging.warning("At least one wanted encryption type is not "
                            "supported by gmsad. Remaining mask: %d", enctypes)

    def write(self, filename: str) -> None:
        """
        Write the current entries into the keytab file.
        Existing content is overwriten.
        """
        logging.debug("Writing %d keytab entries into %s", len(self.entries), filename)
        with open(filename, 'w+b') as fd:
            self.to_stream(fd)
