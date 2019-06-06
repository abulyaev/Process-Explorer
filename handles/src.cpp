#include <windows.h>
#include <imagehlp.h>
#include <stdio.h> // horrors! mixing stdio and C++!
#include <stddef.h>

class MappedImage
{
public:
	bool MapImage(char* fileName);
	int ProcessResultsASLR();
	int ProcessResultsDEP();
	~MappedImage();

private:
	WORD GetCharacteristics();

	template<typename T>
	WORD GetDllCharacteristics();


private:
	HANDLE file_ = INVALID_HANDLE_VALUE;
	HANDLE mapping_ = nullptr;
	void *imageBase_ = nullptr;
	IMAGE_NT_HEADERS* headers_ = nullptr;
	int bitness_ = 0;
};

bool MappedImage::MapImage(char* fileName)
{
	file_ = CreateFile((LPWSTR)fileName, GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);
	if (file_ == INVALID_HANDLE_VALUE) return false;

	mapping_ = CreateFileMapping(file_, NULL, PAGE_READONLY,
		0, 0, NULL);
	if (!mapping_) return false;

	imageBase_ = MapViewOfFile(mapping_, FILE_MAP_READ, 0, 0, 0);
	if (!imageBase_) return false;

	headers_ = ImageNtHeader(imageBase_);
	if (!headers_) return false;
	if (headers_->Signature != IMAGE_NT_SIGNATURE) return false;

	switch (headers_->OptionalHeader.Magic) {
	case IMAGE_NT_OPTIONAL_HDR32_MAGIC: bitness_ = 32; break;
	case IMAGE_NT_OPTIONAL_HDR64_MAGIC: bitness_ = 64; break;
	default: return false;
	}

	return true;
}

MappedImage::~MappedImage()
{
	if (imageBase_) UnmapViewOfFile(imageBase_);
	if (mapping_) CloseHandle(mapping_);
	if (file_ != INVALID_HANDLE_VALUE) CloseHandle(file_);
}

WORD MappedImage::GetCharacteristics()
{
	return headers_->FileHeader.Characteristics;
}

template<typename T>
WORD MappedImage::GetDllCharacteristics()
{
	return reinterpret_cast<T*>(headers_)->
		OptionalHeader.DllCharacteristics;
}


int MappedImage::ProcessResultsASLR()
{
	auto Characteristics = GetCharacteristics();
	auto DllCharacteristics = bitness_ == 32
		? GetDllCharacteristics<IMAGE_NT_HEADERS32>()
		: GetDllCharacteristics<IMAGE_NT_HEADERS64>();
	int ret;
		ret=(DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)? 1 : 0;

		return ret;

}
int MappedImage::ProcessResultsDEP()
{
	auto Characteristics = GetCharacteristics();
	auto DllCharacteristics = bitness_ == 32
		? GetDllCharacteristics<IMAGE_NT_HEADERS32>()
		: GetDllCharacteristics<IMAGE_NT_HEADERS64>();
	int ret;
	ret = (DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) ? 1 : 0;

	return ret;

}
