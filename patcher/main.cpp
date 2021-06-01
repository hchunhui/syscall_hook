#include <stdio.h>
#include <inttypes.h>
#include <Zydis/Zydis.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <set>
#include <queue>

#define PAGESIZE 4096
#define N 5
using namespace std;

unsigned char *elf_read_section(unsigned char *elf, const char *name, unsigned long *addr, size_t *len)
{
	Elf64_Ehdr *ehdr = (Elf64_Ehdr *) elf;
	char *strtab = NULL;
	for (int i = 0; i < ehdr->e_shnum; i++) {
		size_t soff = ehdr->e_shoff + (i * ehdr->e_shentsize);
		Elf64_Shdr *shdr = (Elf64_Shdr *) (elf + soff);
		if (shdr->sh_type == SHT_STRTAB) {
			strtab = (char *) elf + shdr->sh_offset;
		}
	}

	if (!strtab)
		return NULL;

	for (int i = 0; i < ehdr->e_shnum; i++) {
		size_t soff = ehdr->e_shoff + (i * ehdr->e_shentsize);
		Elf64_Shdr *shdr = (Elf64_Shdr *) (elf + soff);
		char *sh_name = strtab + shdr->sh_name;
		if (strcmp(sh_name, name) == 0) {
			if (len)
				*len = shdr->sh_size;
			if (addr)
				*addr = shdr->sh_addr;
			return elf + shdr->sh_offset;
		}
	}

	return NULL;
}

static int emit_prologue(vector<unsigned char> &patch)
{
	// magic number
	patch.push_back(0x55);
	patch.push_back(0xaa);
	patch.push_back(0x00);
	patch.push_back(0xff);
	patch.push_back(0x48);
	patch.push_back(0x4f);
	patch.push_back(0x4f);
	patch.push_back(0x4b);

	// hook addr
	int hook_addr_addr = patch.size();
	patch.push_back(0x00);
	patch.push_back(0x00);
	patch.push_back(0x00);
	patch.push_back(0x00);
	patch.push_back(0x00);
	patch.push_back(0x00);
	patch.push_back(0x00);
	patch.push_back(0x00);
	return hook_addr_addr;
}

static int emit_comm(vector<unsigned char> &patch, int addr_addr)
{
	int addr = patch.size();
	// mov    0x0(%rip), %rax
	int pc = patch.size() + 7;
	int offset = addr_addr - pc;
	patch.push_back(0x48); patch.push_back(0x8b); patch.push_back(0x05);
	patch.push_back(offset & 0xff);
	patch.push_back((offset >> 8) & 0xff);
	patch.push_back((offset >> 16) & 0xff);
	patch.push_back((offset >> 24) & 0xff);
	// test   %rax,%rax
	patch.push_back(0x48); patch.push_back(0x85); patch.push_back(0xc0);
	// je     0x89
	patch.push_back(0x74); patch.push_back(0x41);
	// mov    %rdi,0x10(%rsp)
	patch.push_back(0x48); patch.push_back(0x89); patch.push_back(0x7c); patch.push_back(0x24); patch.push_back(0x10);
	// mov    %rsi,0x18(%rsp)
	patch.push_back(0x48); patch.push_back(0x89); patch.push_back(0x74); patch.push_back(0x24); patch.push_back(0x18);
	// mov    %rdx,0x20(%rsp)
	patch.push_back(0x48); patch.push_back(0x89); patch.push_back(0x54); patch.push_back(0x24); patch.push_back(0x20);
	// mov    %r10,0x28(%rsp)
	patch.push_back(0x4c); patch.push_back(0x89); patch.push_back(0x54); patch.push_back(0x24); patch.push_back(0x28);
	// mov    %r8,0x30(%rsp)
	patch.push_back(0x4c); patch.push_back(0x89); patch.push_back(0x44); patch.push_back(0x24); patch.push_back(0x30);
	// mov    %r9,0x38(%rsp)
	patch.push_back(0x4c); patch.push_back(0x89); patch.push_back(0x4c); patch.push_back(0x24); patch.push_back(0x38);
	// mov    %rsp,%rdi
	patch.push_back(0x48); patch.push_back(0x89); patch.push_back(0xe7);
	// callq  *%rax
	patch.push_back(0xff); patch.push_back(0xd0);
	// mov    0x10(%rsp),%rdi
	patch.push_back(0x48); patch.push_back(0x8b); patch.push_back(0x7c); patch.push_back(0x24); patch.push_back(0x10);
	// mov    0x18(%rsp),%rsi
	patch.push_back(0x48); patch.push_back(0x8b); patch.push_back(0x74); patch.push_back(0x24); patch.push_back(0x18);
	// mov    0x20(%rsp),%rdx
	patch.push_back(0x48); patch.push_back(0x8b); patch.push_back(0x54); patch.push_back(0x24); patch.push_back(0x20);
	// mov    0x28(%rsp),%r10
	patch.push_back(0x4c); patch.push_back(0x8b); patch.push_back(0x54); patch.push_back(0x24); patch.push_back(0x28);
	// mov    0x30(%rsp),%r8
	patch.push_back(0x4c); patch.push_back(0x8b); patch.push_back(0x44); patch.push_back(0x24); patch.push_back(0x30);
	// mov    0x38(%rsp),%r9
	patch.push_back(0x4c); patch.push_back(0x8b); patch.push_back(0x4c); patch.push_back(0x24); patch.push_back(0x38);
	// retq
	patch.push_back(0xc3);

	for(; patch.size() % 16; ) {
		patch.push_back(0x90);
	}

	return addr;
}

static void emit_hook(vector<unsigned char> &patch, int comm_addr)
{
	// sub    $0x1000,%rsp
	patch.push_back(0x48); patch.push_back(0x81); patch.push_back(0xec);
	patch.push_back(0x00); patch.push_back(0x10); patch.push_back(0x00); patch.push_back(0x00);
	// mov    %rax,(%rsp)
	patch.push_back(0x48); patch.push_back(0x89); patch.push_back(0x04); patch.push_back(0x24);

	// callq  comm
	int pc = patch.size() + 5;
	int offset = comm_addr - pc;
	patch.push_back(0xe8);
	patch.push_back(offset & 0xff);
	patch.push_back((offset >> 8) & 0xff);
	patch.push_back((offset >> 16) & 0xff);
	patch.push_back((offset >> 24) & 0xff);

	// add    $0x1000,%rsp
	patch.push_back(0x48); patch.push_back(0x81); patch.push_back(0xc4);
	patch.push_back(0x00); patch.push_back(0x10); patch.push_back(0x00); patch.push_back(0x00);

	// test   %rax,%rax
	patch.push_back(0x48); patch.push_back(0x85); patch.push_back(0xc0);
	// mov    -0x1000(%rsp),%rax
	patch.push_back(0x48); patch.push_back(0x8b); patch.push_back(0x84); patch.push_back(0x24);
	patch.push_back(0x00); patch.push_back(0xf0); patch.push_back(0xff); patch.push_back(0xff);
	// jne
	patch.push_back(0x75); patch.push_back(0x02);
	// syscall
	patch.push_back(0x0f); patch.push_back(0x05);
}

static
void emit_patch(vector<unsigned char> &patch, unsigned long patch_offset, unsigned long next,
		unsigned char *data, unsigned long offset, int len, unsigned long addr,
		vector<unsigned long> &reloc1, vector<unsigned long> &reloc2)
{
	if (next == 0)
		next = addr + 5;
	int pjmp_addr = next /* - patch_vaddr */ - patch.size() - 5;
	patch.push_back(0xe9);  // jmpq
	reloc2.push_back(patch.size());
	patch.push_back((pjmp_addr >> 0) & 0xff);
	patch.push_back((pjmp_addr >> 8) & 0xff);
	patch.push_back((pjmp_addr >> 16) & 0xff);
	patch.push_back((pjmp_addr >> 24) & 0xff);
	for(; patch.size() % 16; ) {
		patch.push_back(0x90);
	}

	int jmp_addr = /* patch_vaddr + */ patch_offset - (addr + 5);
	data[offset + 0] = 0xe9;  // jmpq
	data[offset + 1] = (jmp_addr >> 0) & 0xff;
	data[offset + 2] = (jmp_addr >> 8) & 0xff;
	data[offset + 3] = (jmp_addr >> 16) & 0xff;
	data[offset + 4] = (jmp_addr >> 24) & 0xff;
	for (int j = 0; j < len - 5; j++) {
		data[offset + 5 + j] = 0x90;
	}
	reloc1.push_back(offset + 1);
}

struct instr_info {
	unsigned long addr;
	unsigned long offset;
	int prev_room;
	bool is_syscall;
	int length;
};

bool operator<(const instr_info &a, const instr_info &b)
{
	return a.addr < b.addr;
}

static void rewrite(unsigned char *data, size_t len, unsigned long vaddr)
{
	ZydisDecoder decoder;
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);

	int state = 0;

	size_t offset = 0;
	ZydisDecodedInstruction instr;
	while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, data + offset, len - offset,
						     &instr)))
	{
		if (instr.mnemonic == ZYDIS_MNEMONIC_MOV &&
		    data[offset] == 0xb8 &&
		    instr.length == 5) {
			state = 1;
		} else {
			if (state == 1 &&
			    instr.mnemonic == ZYDIS_MNEMONIC_LEA &&
			    instr.length == 7 &&
			    data[offset] == 0x48 &&
			    data[offset + 1] == 0x8d &&
			    (data[offset + 2] == 0x3d || data[offset + 2] == 0xba)) {
				state = 2;
			} else if (state == 2 &&
				   instr.mnemonic == ZYDIS_MNEMONIC_SYSCALL) {
				unsigned char temp[5];
				memcpy(temp, data + offset - 7 - 5, 5);

				int d = data[offset - 4] & 0xff;
				d |= (data[offset - 3] & 0xff) << 8;
				d |= (data[offset - 2] & 0xff) << 16;
				d |= (data[offset - 1] & 0xff) << 24;
				if (data[offset - 5] == 0x3d) {
					d += 5;
				}
				data[offset - 7 - 5] = data[offset - 7];
				data[offset - 6 - 5] = data[offset - 6];
				data[offset - 5 - 5] = data[offset - 5];
				data[offset - 4 - 5] = (d >> 0) & 0xff;
				data[offset - 3 - 5] = (d >> 8) & 0xff;
				data[offset - 2 - 5] = (d >> 16) & 0xff;
				data[offset - 1 - 5] = (d >> 24) & 0xff;
				memcpy(data + offset - 5, temp, 5);
				state = 0;
			} else {
				state = 0;
			}
		}
		offset += instr.length;
	}
}

static void disasm(unsigned char *data, size_t len, unsigned long vaddr, set<instr_info> &instrs)
{
	ZydisDecoder decoder;
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);

	size_t offset = 0;
	int prev_room = 0;
	ZydisDecodedInstruction instr;
	while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, data + offset, len - offset,
						     &instr)))
	{
		if (instr.mnemonic == ZYDIS_MNEMONIC_SYSCALL) {
			instrs.insert({vaddr, offset, prev_room, true, instr.length});
		}

		if (instr.mnemonic == ZYDIS_MNEMONIC_NOP) {
			instrs.insert({vaddr, offset, prev_room, false, instr.length});
		}

		if (instr.mnemonic == ZYDIS_MNEMONIC_MOV ||
		    instr.mnemonic == ZYDIS_MNEMONIC_MOVUPS || instr.mnemonic == ZYDIS_MNEMONIC_MOVSXD ||
		    instr.mnemonic == ZYDIS_MNEMONIC_XOR ||
		    instr.mnemonic == ZYDIS_MNEMONIC_ADD || instr.mnemonic == ZYDIS_MNEMONIC_SUB ||
		    instr.mnemonic == ZYDIS_MNEMONIC_OR || instr.mnemonic == ZYDIS_MNEMONIC_AND ||
		    instr.mnemonic == ZYDIS_MNEMONIC_NOT) {
			// XXX
			if (instr.length >= 3) {
				prev_room = instr.length;
			} else {
				prev_room += instr.length;
			}
		} else {
			prev_room = 0;
		}

		offset += instr.length;
		vaddr += instr.length;
	}
}

instr_info fix_nop(unsigned char *data, instr_info n)
{
	if (n.length > 2) {
		data[n.offset] = 0xeb;
		data[n.offset + 1] = n.length - 2;
		for (int i = 0; i < n.length - 2; i++)
			data[n.offset + 2 + i] = 0x90;
	}
	n.addr += 2;
	n.offset += 2;
	n.length -= 2;
	return n;
}

int main(int argc, char **argv)
{
	if (argc < 3)
		return 1;

	bool workaround = false;
	if (argc > 3)
		workaround = true;

	char *file = argv[1];
	struct stat statbuf;
	if (stat(file, &statbuf) < 0)
		return 1;
	int fd = open(file, O_RDONLY);
	unsigned char *elf = (unsigned char *) mmap(NULL, statbuf.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

	unsigned long vaddr;
	size_t len;
	unsigned char *data = elf_read_section(elf, ".text", &vaddr, &len);
	if (!data)
		return 1;

	set<instr_info> instrs;
	rewrite(data, len, vaddr);
	disasm(data, len, vaddr, instrs);

	vector<unsigned char> patch;
	int hook_addr_addr = emit_prologue(patch);
	int comm_addr = emit_comm(patch, hook_addr_addr);

	queue<instr_info> nopq, sysq;
	struct instr_info nop{0, 0, 0, false, 0};
	vector<unsigned long> reloc1, reloc2;
	for (auto &i : instrs) {
		if (i.is_syscall) {
			if (nop.addr != 0) {
				nopq.push(fix_nop(data, nop));
				nop.addr = 0;
			}
			if (i.prev_room < 3)
				sysq.push(i);
			else {
				unsigned long offset = i.offset - i.prev_room;
				unsigned long addr = i.addr - i.prev_room;
				unsigned long patch_offset = patch.size();
				for (int j = 0; j < i.prev_room; j++)
					patch.push_back(data[offset + j]);
				emit_hook(patch, comm_addr);
				emit_patch(patch, patch_offset, i.addr + 2,
					   data, offset, i.prev_room + 2, addr,
					   reloc1, reloc2);
			}
		} else {
			if (nop.addr == 0) {
				nop = i;
			} else {
				if (nop.addr + nop.length == i.addr) {
					nop.length += i.length;
				} else {
					nopq.push(fix_nop(data, nop));
					nop = i;
				}
			}
		}
	}

	if (nop.addr != 0)
		nopq.push(fix_nop(data, nop));

	int c = 0;
	while (!sysq.empty()) {
		auto k = sysq.front();
		bool found = false;
		while (!nopq.empty()) {
			auto j = nopq.front();
			while (!nopq.empty() && j.length < N) {
				nopq.pop();
				j = nopq.front();
			}

			if (nopq.empty())
				break;

			if (j.addr < k.addr) {
				if (j.length > N) {
					nopq.front().length -= N;
					nopq.front().addr += N;
					nopq.front().offset += N;
				} else {
					nopq.pop();
				}
				if (k.addr - j.addr <= 128) {
					printf("patch - %08lX\n", k.addr);
					unsigned long patch_offset = patch.size();
					emit_hook(patch, comm_addr);

					data[k.offset] = 0xeb;
					data[k.offset + 1] = (j.addr) - (k.addr + 2);

					emit_patch(patch, patch_offset, k.addr + 2,
						   data, j.offset, j.length, j.addr,
						   reloc1, reloc2);

					found = true;
					break;
				}
			} else {
				if (j.addr - k.addr <= 127) {
					printf("patch + %08lX\n", k.addr);
					if (j.length > N) {
						nopq.front().length -= N;
						nopq.front().addr += N;
						nopq.front().offset += N;
					} else {
						nopq.pop();
					}

					unsigned long patch_offset = patch.size();
					emit_hook(patch, comm_addr);

					data[k.offset] = 0xeb;
					data[k.offset + 1] = (j.addr) - (k.addr + 2);

					emit_patch(patch, patch_offset, k.addr + 2,
						   data, j.offset, j.length, j.addr,
						   reloc1, reloc2);
					found = true;
				}
				break;
			}
		}
		if (found) {
			sysq.pop();
		} else {
			printf("fail %d %08lX\n", ++c, k.addr);
			sysq.pop();
		}
	}

	auto hdr = (Elf64_Ehdr *) elf;
	int patch_offset = (statbuf.st_size + PAGESIZE - 1) / PAGESIZE * PAGESIZE;
	unsigned long patch_vaddr = 0;

	for (int i = 0; i < hdr->e_phnum; i++) {
		auto phdr = (Elf64_Phdr *) (elf + hdr->e_phoff) + i;
		unsigned long a = (phdr->p_vaddr + phdr->p_memsz + PAGESIZE - 1) / PAGESIZE * PAGESIZE;
		if (a > patch_vaddr) patch_vaddr = a;
	}
	printf("got offset 0x%x, vaddr 0x%x\n", patch_offset, patch_vaddr);

	if (workaround) {
		unsigned long load_vaddr = 0;
		for (int i = 0; i < hdr->e_phnum; i++) {
			auto phdr = (Elf64_Phdr *) (elf + hdr->e_phoff) + i;
			if (phdr->p_type == PT_LOAD) {
				load_vaddr = phdr->p_vaddr;
				break;
			}
		}

		unsigned long new_offset = patch_vaddr - load_vaddr;
		if (patch_offset < new_offset) {
			printf("set patch_offset = 0x%x\n", new_offset);
			patch_offset = new_offset;
		}
	}

	vector<unsigned char> out(elf, elf + statbuf.st_size);
	int patch_size = (patch.size() + PAGESIZE - 1) / PAGESIZE * PAGESIZE;
	out.resize(patch_offset + patch_size, 0);
	memcpy(out.data() + patch_offset, patch.data(), patch.size());

	int phdr_size = (hdr->e_phnum + 1) * sizeof(Elf64_Phdr);
	Elf64_Phdr nphent = {0};
	nphent.p_type = PT_LOAD;
	nphent.p_offset = patch_offset;
	nphent.p_vaddr = nphent.p_paddr = patch_vaddr;
	nphent.p_filesz = nphent.p_memsz = patch_size + phdr_size;
	nphent.p_flags = PF_R | PF_W | PF_X;
	nphent.p_align = PAGESIZE;
	out.insert(out.end(), elf + hdr->e_phoff, elf + hdr->e_phoff + phdr_size - hdr->e_phentsize);
	out.insert(out.end(), (unsigned char *) &nphent, (unsigned char *) (&nphent + 1));

	hdr = (Elf64_Ehdr *) out.data();
	hdr->e_phoff = patch_offset + patch_size;
	hdr->e_phnum++;

	for (int i = 0; i < hdr->e_phnum; i++) {
		auto phdr = (Elf64_Phdr *) (out.data() + hdr->e_phoff) + i;
		if (phdr->p_type == PT_PHDR) {
			phdr->p_offset = hdr->e_phoff;
			phdr->p_vaddr = phdr->p_paddr = patch_vaddr + patch_size;
			phdr->p_filesz = phdr->p_memsz = phdr_size;
			break;
		}
	}

	auto data2 = elf_read_section(out.data(), ".text", NULL, NULL);
	for (int i : reloc1) {
		int offset = data2[i] & 0xff;
		offset |= (data2[i + 1] & 0xff) << 8;
		offset |= (data2[i + 2] & 0xff) << 16;
		offset |= (data2[i + 3] & 0xff) << 24;
		offset += patch_vaddr;
		data2[i + 0] = (offset >> 0) & 0xff;
		data2[i + 1] = (offset >> 8) & 0xff;
		data2[i + 2] = (offset >> 16) & 0xff;
		data2[i + 3] = (offset >> 24) & 0xff;
	}

	data2 = out.data();
	for (int i : reloc2) {
		i += patch_offset;
		int offset = data2[i] & 0xff;
		offset |= (data2[i + 1] & 0xff) << 8;
		offset |= (data2[i + 2] & 0xff) << 16;
		offset |= (data2[i + 3] & 0xff) << 24;
		offset -= patch_vaddr;
		data2[i + 0] = (offset >> 0) & 0xff;
		data2[i + 1] = (offset >> 8) & 0xff;
		data2[i + 2] = (offset >> 16) & 0xff;
		data2[i + 3] = (offset >> 24) & 0xff;
	}

	FILE *fp = fopen(argv[2], "wb");
	if (!fp) {
		fprintf(stderr, "open %s failed\n", argv[2]);
		return 1;
	}

	fwrite(out.data(), 1, out.size(), fp);

	fclose(fp);

	return 0;
}
