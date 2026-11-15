# axml.py — minimal Android binary XML (AXML) reader: enough for AndroidManifest.xml.
import struct

CHUNK_STRING_POOL = 0x001C0001
CHUNK_START_TAG = 0x00102002
CHUNK_END_TAG = 0x00102003
CHUNK_START_ELEMENT = 0x01010002
CHUNK_END_ELEMENT = 0x01010003


def parse(data):
    """Return (string_pool, elements) where elements = list of (tag, {attr: value})."""
    if len(data) < 8 or data[:4] != b"\x03\x00\x08\x00":
        raise ValueError("not a binary XML file")
    # ---- string pool
    off = 8
    strings = []
    while off < len(data):
        ctype, hdr, size = struct.unpack_from("<HHI", data, off)
        if ctype == 0x0001 and hdr == 0x001C:   # RES_STRING_POOL_TYPE
            str_count, style_count, flags, str_start, style_start = struct.unpack_from(
                "<IIIII", data, off + 8)
            utf8 = bool(flags & (1 << 8))
            offsets = struct.unpack_from("<%dI" % str_count, data, off + 28)
            base = off + 8 + str_start
            for o in offsets:
                p = base + o
                if utf8:
                    # 2 length bytes (uleb-ish), then the string
                    n = data[p]
                    p += 1
                    if n & 0x80:
                        n = ((n & 0x7f) << 8) | data[p]
                        p += 1
                    s = data[p:p + n].decode("utf-8", "replace")
                else:
                    n = struct.unpack_from("<H", data, p)[0]
                    p += 2
                    if n & 0x8000:
                        n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", data, p)[0]
                        p += 2
                    s = data[p:p + n * 2].decode("utf-16-le", "replace")
                strings.append(s)
            break
        if typ == 0x0001 and hdr == 0x0008:      # RES_XML_RESOURCE_MAP
            off += size
            continue
        break

    # ---- walk the chunks
    elements = []
    off = 8
    while off + 8 <= len(data):
        ctype, hdr, size = struct.unpack_from("<HHI", data, off)
        if size == 0:
            break
        if ctype == 0x0102 and hdr in (0x0008, 0x0010):
            # node header: lineNumber(I) comment(I) | ns(i) name(i)
            #                attributeStart(H) attributeSize(H) attributeCount(H)
            #                idIndex(H) classIndex(H) styleIndex(H)
            ns, name, astart, asize, acount, ididx, cidx, sidx = struct.unpack_from(
                "<iiHHHHHH", data, off + 16)
            attrs = {}
            aoff = off + 36
            for i in range(acount):
                a = aoff + i * 20
                ans, aname, araw, atyped = struct.unpack_from("<iiII", data, a)
                val = araw
                if atyped == 0x03:     # string
                    val = strings[araw] if 0 <= araw < len(strings) else araw
                attrs[strings[aname] if 0 <= aname < len(strings) else aname] = val
            elements.append((strings[name] if 0 <= name < len(strings) else name, attrs))
        off += size
    return strings, elements


if __name__ == "__main__":
    import sys, zipfile
    apk = sys.argv[1]
    z = zipfile.ZipFile(apk)
    data = z.read("AndroidManifest.xml")
    strings, elements = parse(data)
    for tag, attrs in elements:
        interesting = {k: v for k, v in attrs.items()
                       if k in ("name", "package", "permission", "android:permission",
                                "value", "resource", "process", "exported", "authorities",
                                "foregroundServiceType", "scheme", "host")}
        print(f"<{tag}> {interesting}")
