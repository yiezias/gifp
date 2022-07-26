#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define BUF_SIZE 131072

#define NDEBUG

#ifndef NDEBUG
#define PRINTF(format, ...) printf(format, __VA_ARGS__)
#else
#define PRINTF(format, ...)
#endif

struct coff_header {
	uint16_t Machine;
	uint16_t NumberOfSection;
	uint32_t TimeDateStamp;
	uint32_t PointerToSymbolTable;
	uint32_t NumberOfSymbols;
	uint16_t SizeOfOptionalHeader;
	uint16_t Feature;
};

struct sec_table {
	char Name[8];
	uint32_t VirtualSize;
	uint32_t VirtualAddress;
	uint32_t SizeOfRawData;
	uint32_t PointerToRawData;
	uint32_t PointerToRelocations;
	uint32_t PointerToLinenumbers;
	uint16_t NumberOfRelocations;
	uint16_t NumberOfLinenumbers;
	uint32_t Feature;
};

struct RcDirTable {
	uint32_t Feature;
	uint32_t TimeDateStamp;
	uint16_t MajVer;
	uint16_t MinVer;
	uint16_t NameEntryCnt;
	uint16_t IdEntryCnt;
};

struct RcDirEntry {
	uint32_t IdOrName;
	int32_t DataOrSubDir;
};

struct RcDataEntry {
	int32_t rva;
	uint32_t size;
	uint32_t codepage;
	uint32_t reserve;
};

struct icohead {
	uint16_t rsv0;
	uint16_t cls;
	uint16_t cnt;
};

struct icoinfo {
	uint8_t wid;
	uint8_t hei;
	uint8_t clr;
	uint8_t nouse;
	uint32_t rsv;
	uint32_t size;
	uint32_t off;
};

FILE *in;
uint32_t pdr;

uint32_t getRcOff(uint8_t *buf) {
	struct coff_header *coff_off =
		(struct coff_header *)(*(int *)(buf + 0x3c) + 4 + buf);
	struct sec_table *st =
		(void *)coff_off + 20 + coff_off->SizeOfOptionalHeader;
	int nosec = coff_off->NumberOfSection;
	PRINTF("节数：0x%x\n", nosec);
	PRINTF("可选头大小：0x%x\n", coff_off->SizeOfOptionalHeader);
	char rsrc_name[8] = ".rsrc";
	int rsrc_off = 0;
	while (rsrc_off != nosec) {
		if (!strcmp(rsrc_name, st[rsrc_off].Name)) {
			break;
		}
		++rsrc_off;
	}
	assert(rsrc_off < nosec);
	PRINTF("节表地址：0x%x\n", st[rsrc_off].PointerToRawData);
	PRINTF("虚拟地址：0x%x\n", st[rsrc_off].VirtualAddress);
	pdr = st[rsrc_off].PointerToRawData - st[rsrc_off].VirtualAddress;
	PRINTF("节表地址减虚拟地址：%d\n", pdr);
	return st[rsrc_off].PointerToRawData;
}

void depart(struct RcDirTable *rdt, struct RcDirTable *top) {
	int ns = rdt->NameEntryCnt + rdt->IdEntryCnt;
	PRINTF("图标资源数：0x%x\n", ns);
	struct RcDirEntry *ebeg = (struct RcDirEntry *)(rdt + 1);
	for (int i = 0; i != ns; ++i) {
		struct RcDirEntry *rde = ebeg + i;
		int32_t off;
		assert(rde->DataOrSubDir & 0x80000000);
		off = 0x7fffffff & rde->DataOrSubDir;
		PRINTF("\n偏移一：0x%x\n", off);
		rdt = (void *)top + off;
		struct RcDirEntry *eb = (struct RcDirEntry *)(rdt + 1);
		for (int j = 0; j != rdt->IdEntryCnt; ++j) {
			char name[10];
			static int cnt = 0;
			sprintf(name, "%d.ico", cnt++);
			PRINTF("\n文件%s：\n", name);
			rde = eb + j;
			off = rde->DataOrSubDir;
			PRINTF("偏移二：0x%x\n", off);
			struct RcDataEntry *datae = (void *)top + off;
			PRINTF("rva：0x%x\n", datae->rva);
			int32_t foff = datae->rva + pdr;
			uint32_t size = datae->size + sizeof(struct icohead)
					+ sizeof(struct icoinfo);
			assert(sizeof(struct icohead) + sizeof(struct icoinfo)
			       == 22);
			struct icohead *buf = malloc(size);
			assert(buf);
			memset(buf, 0, size);
			buf->cls = buf->cnt = 1;
			struct icoinfo *ii = (struct icoinfo *)(buf + 1);
			ii->off =
				sizeof(struct icohead) + sizeof(struct icoinfo);
			ii->size = datae->size;
			PRINTF("偏移终：0x%x\n", foff);
			PRINTF("输出长度：0x%x\n", datae->size);
			fseek(in, foff, SEEK_SET);
			fread((void *)buf + sizeof(struct icohead)
				      + sizeof(struct icoinfo),
			      datae->size, 1, in);
			FILE *out = fopen(name, "wb");
			assert(out);
			fwrite(buf, size, 1, out);
			fclose(out);
			free(buf);
		}
	}
}

int32_t getPicRc(struct RcDirTable *rdt) {
	int ns = rdt->NameEntryCnt + rdt->IdEntryCnt;
	PRINTF("名字标识的条目0x%x\n", rdt->NameEntryCnt);
	PRINTF("id表示的条目：0x%x\n", rdt->IdEntryCnt);
	struct RcDirEntry *ebeg = (struct RcDirEntry *)(rdt + 1);
	for (int i = 0; i != ns; ++i) {
		if (ebeg[i].IdOrName == 3) {
			return 0x7fffffff & ebeg[i].DataOrSubDir;
		}
	}
	return 0;
}

int main(int argc, char **argv) {
	assert(argc == 2);
	uint8_t buf[BUF_SIZE];
	in = fopen(argv[1], "rb");
	assert(in);
	fread(buf, BUF_SIZE, 1, in);
	uint32_t rcoff = getRcOff(buf);

	fseek(in, rcoff, SEEK_SET);
	fread(buf, BUF_SIZE, 1, in);
	struct RcDirTable *rdt = (void *)buf;
	int32_t off = getPicRc(rdt);
	assert(off);
	depart((void *)rdt + off, rdt);
	fclose(in);
}
