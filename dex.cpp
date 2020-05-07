// dex.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <unordered_map>
#include <unordered_set>
#include <random>
#include <windows.h>

static uint8_t buffer[8 * 1024 * 1024];

static constexpr size_t kSha1DigestSize = 20;

// Raw header_item.
struct Header {
	uint8_t magic_[8] = {};
	uint32_t checksum_ = 0;  // See also location_checksum_
	uint8_t signature_[kSha1DigestSize] = {};
	uint32_t file_size_ = 0;  // size of entire file
	uint32_t header_size_ = 0;  // offset to start of next section
	uint32_t endian_tag_ = 0;
	uint32_t link_size_ = 0;  // unused
	uint32_t link_off_ = 0;  // unused
	uint32_t map_off_ = 0;  // unused
	uint32_t string_ids_size_ = 0;  // number of StringIds
	uint32_t string_ids_off_ = 0;  // file offset of StringIds array
	uint32_t type_ids_size_ = 0;  // number of TypeIds, we don't support more than 65535
	uint32_t type_ids_off_ = 0;  // file offset of TypeIds array
	uint32_t proto_ids_size_ = 0;  // number of ProtoIds, we don't support more than 65535
	uint32_t proto_ids_off_ = 0;  // file offset of ProtoIds array
	uint32_t field_ids_size_ = 0;  // number of FieldIds
	uint32_t field_ids_off_ = 0;  // file offset of FieldIds array
	uint32_t method_ids_size_ = 0;  // number of MethodIds
	uint32_t method_ids_off_ = 0;  // file offset of MethodIds array
	uint32_t class_defs_size_ = 0;  // number of ClassDefs
	uint32_t class_defs_off_ = 0;  // file offset of ClassDef array
	uint32_t data_size_ = 0;  // size of data section
	uint32_t data_off_ = 0;  // file offset of data section
};

// Raw string_id_item.
struct StringId {
	uint32_t string_data_off_;  // offset in bytes from the base address
};

// Raw method_id_item.
struct MethodId {
	uint16_t class_idx_; // index into type_ids_ array for defining class
	uint16_t proto_idx_; // index into proto_ids_ array for method prototype
	uint32_t name_idx_;  // index into string_ids_ array for method name
};

// Raw field_id_item.
struct FieldId {
	uint16_t class_idx_; // index into type_ids_ array for defining class
	uint16_t type_idx_;  // index into type_ids_ array for field type
	uint32_t name_idx_;  // index into string_ids_ array for field name
};

// Raw type_id_item.
struct TypeId {
	uint32_t descriptor_idx_;  // index into string_ids
};

// Reads an unsigned LEB128 value, updating the given pointer to point
// just past the end of the read value. This function tolerates
// non-zero high-order bits in the fifth encoded byte.
static inline uint32_t DecodeUnsignedLeb128(const uint8_t** data) {
	const uint8_t* ptr = *data;
	int result = *(ptr++);
	if (result > 0x7f) {
		int cur = *(ptr++);
		result = (result & 0x7f) | ((cur & 0x7f) << 7);
		if (cur > 0x7f) {
			cur = *(ptr++);
			result |= (cur & 0x7f) << 14;
			if (cur > 0x7f) {
				cur = *(ptr++);
				result |= (cur & 0x7f) << 21;
				if (cur > 0x7f) {
					// Note: We don't check to see if cur is out of range here,
					// meaning we tolerate garbage in the four high-order bits.
					cur = *(ptr++);
					result |= cur << 28;
				}
			}
		}
	}
	*data = ptr;
	return static_cast<uint32_t>(result);
}

static inline uint8_t *EncodeUnsignedLeb128(uint8_t *dest, uint32_t value) {
	uint8_t out = value & 0x7f;
	value >>= 7;
	while (value != 0) {
		*dest++ = out | 0x80;
		out = value & 0x7f;
		value >>= 7;
	}
	*dest++ = out;
	return dest;
}

static inline uint32_t GetUTFCharsSize(const uint8_t *const dd, const uint32_t ll) {
	uint32_t s = 0, l = 0;
	while (dd[s] != '\0') {
		if (dd[s] <= 0b01111111u) {
			++s;
			++l;
		} else if (dd[s] <= 0b11011111u) {
			s += 2;
			++l;
		} else if (dd[s] <= 0b11101111u) {
			s += 3;
			++l;
		} else {
			*reinterpret_cast<int *>(NULL) = NULL;
		}
	}
	/*
	0000 0000-0000 007F:0xxxxxxx
	0000 0080-0000 07FF:110xxxxx 10xxxxxx
	0000 0800-0000 FFFF:1110xxxx 10xxxxxx 10xxxxxx
	0001 0000-001F FFFF:11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
	0020 0000-03FF FFFF:111110xx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx
	0400 0000-7FFF FFFF:1111110x 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx
	*/
	if (ll != l) {
		*reinterpret_cast<int *>(NULL) = NULL;
	}
	return s;
}

static inline std::string RandomUniqueLegalName(uint8_t *const dd, const uint32_t l, std::unordered_set<std::string> &set) {
	static const char cs[] = "QT9qrUV7GHIJKLMN8EFOPhijkW56lmnwxyzABXYZ012potuvRSbsefgadc34CD";
	static std::random_device r;
	static std::default_random_engine e(r());
	static std::uniform_int_distribution<> u(0, _countof(cs) - 2);

	static uint8_t d[sizeof(buffer) / 1024];

	bool b;
	uint32_t y;

__retry:
	b = false;
	y = 0;
	memcpy(d, dd, l);
	for (; y < l; ++y) {
		if ((d[y] >= '0' && d[y] <= '9') || (d[y] >= 'A' && d[y] <= 'Z') || (d[y] >= 'a' && d[y] <= 'z')) {
			continue;
		}
		switch (d[y]) {
		case '.':
		case '_':
		case '*':
		case '(':
		case ')':
		case '>':
		case '<':
		case ';':
		case '/':
		case '$':
			continue;
		}

		b = true;

		d[y] = cs[u(e)];
		if (d[y] == '\0') {
			*reinterpret_cast<int *>(NULL) = NULL;
		}

		if (y == 0) {
			while (d[0] >= '0' && d[0] <= '9') {
				d[0] = cs[u(e)];
			}
		} else {
			switch (d[y - 1]) {
			case '/':
			case '.':
			case '$':
				while (d[y] >= '0' && d[y] <= '9') {
					d[y] = cs[u(e)];
				}
			}
		}
	}

	{
		std::string s(reinterpret_cast<const char *>(d), l);
		if (!b) {
			set.insert(s);
			return s;
		}
		if (set.find(s) == set.end()) {
			set.insert(s);
			return s;
		}
	}

	goto __retry;
}

static inline void ReplaceUnicodeChars(const StringId *p, std::unordered_set<std::string> &set,
									   std::unordered_map<std::string, std::string> &map) {
	const uint8_t *d = reinterpret_cast<uint8_t *>(buffer + p->string_data_off_);
	uint8_t *const dd = const_cast<uint8_t *>(d);
	const uint32_t s = GetUTFCharsSize(d, DecodeUnsignedLeb128(&d));
	if (s > 0) {
		std::string ds(reinterpret_cast<const char *>(d), s);
		std::unordered_map<std::string, std::string>::iterator &&k = map.find(ds);
		std::string r;
		if (k != map.end()) {
			r = k->second;
		} else {
			r = RandomUniqueLegalName(const_cast<uint8_t *>(d), s, set);
			map.insert(std::pair<std::string, std::string> {ds, r});
		}
		EncodeUnsignedLeb128(dd, static_cast<uint32_t>(r.length()));
		memcpy(const_cast<uint8_t *>(d), r.data(), r.length());
	}
}

int main()
{
    FILE *f = fopen("C:\\Users\\Administrator\\AppData\\Local\\Temp\\pull\\classes.dex", "rb");
    fseek(f, 0, SEEK_END);
    const long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    fread_s(buffer, sizeof(buffer), 1, size, f);
    fclose(f);

	const Header *const h = reinterpret_cast<Header *>(buffer);
	std::unordered_set<std::string> set(h->string_ids_size_);
	std::unordered_map<std::string, std::string> map(h->string_ids_size_);
	for (uint32_t i = 0; i < h->method_ids_size_; ++i) {
		const MethodId *m = reinterpret_cast<MethodId *>(buffer + h->method_ids_off_) + i;
		const StringId *p = reinterpret_cast<StringId *>(buffer + h->string_ids_off_) + m->name_idx_;
		ReplaceUnicodeChars(p, set, map);
	}
	for (uint32_t i = 0; i < h->field_ids_size_; ++i) {
		const FieldId *m = reinterpret_cast<FieldId *>(buffer + h->field_ids_off_) + i;
		const StringId *p = reinterpret_cast<StringId *>(buffer + h->string_ids_off_) + m->name_idx_;
		ReplaceUnicodeChars(p, set, map);
	}
	for (uint32_t i = 0; i < h->type_ids_size_; ++i) {
		const TypeId *m = reinterpret_cast<TypeId *>(buffer + h->type_ids_off_) + i;
		const StringId *p = reinterpret_cast<StringId *>(buffer + h->string_ids_off_) + m->descriptor_idx_;
		ReplaceUnicodeChars(p, set, map);
	}
	// Annotations
	for (uint32_t i = 0; i < h->string_ids_size_; ++i) {
		const StringId *p = reinterpret_cast<StringId *>(buffer + h->string_ids_off_) + i;
		const uint8_t *d = reinterpret_cast<uint8_t *>(buffer + p->string_data_off_);
		uint8_t *const dd = const_cast<uint8_t *>(d);
		const uint32_t s = GetUTFCharsSize(d, DecodeUnsignedLeb128(&d));
		if (d[0] == 'L' && d[s - 1] == '<') {
			const_cast<uint8_t *>(d)[s - 1] = ';';

			std::string ds(reinterpret_cast<const char *>(d), s);
			std::unordered_map<std::string, std::string>::iterator &&k = map.find(ds);
			if (k != map.end()) {
				std::string &r = k->second;
				const uint32_t rl = static_cast<uint32_t>(r.length());
				EncodeUnsignedLeb128(dd, rl);
				memcpy(const_cast<uint8_t *>(d), r.data(), rl);
				const_cast<uint8_t *>(d)[rl - 1] = '<';
			} else {
				*reinterpret_cast<int *>(NULL) = NULL;
			}
		}
	}

	FILE *o = fopen("C:\\Users\\Administrator\\AppData\\Local\\Temp\\pull\\classes_out.dex", "wb");
	fwrite(buffer, 1, h->file_size_, o);
	fclose(o);

    std::cout << "Done!\n";
}
