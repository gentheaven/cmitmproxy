#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <brotli/decode.h>
#include <brotli/encode.h>
#include <zlib/zlib.h>

//Brotli: br

//brotli.exe -d -f enc.js -o decode.js
char* br_decompress(char* buf, size_t buf_len, size_t* out_len)
{
	BrotliDecoderState* state = BrotliDecoderCreateInstance(NULL, NULL, NULL);
	if (!state) {
		return NULL;
	}

	size_t output_size = buf_len * 5;
	size_t available_in = buf_len;
	uint8_t* output_data = (uint8_t*)malloc(output_size);
	const uint8_t* next_in = buf;
	size_t available_out = output_size;
	uint8_t* next_out = output_data;
	BrotliDecoderResult result;

	result = BrotliDecoderDecompressStream(
			state,
			&available_in,
			&next_in,
			&available_out,
			&next_out,
			out_len
			);

	if (result != BROTLI_DECODER_RESULT_SUCCESS) {
		fprintf(stderr, "decode error: %d\n", result);
		BrotliDecoderDestroyInstance(state);
		free(output_data);
		return NULL;
	}

	BrotliDecoderDestroyInstance(state);
	return output_data;
}

//.\brotli.exe -f dec.js -o encode.js
char* br_compress(char* buf, size_t buf_len, size_t* out_len)
{
	int quality = 0;
	int lgwin = 18;

	*out_len = BrotliEncoderMaxCompressedSize(buf_len);
	unsigned char* compressed_data = (unsigned char*)malloc(*out_len);

	BROTLI_BOOL result = BrotliEncoderCompress(
			quality,
			lgwin,
			BROTLI_DEFAULT_MODE,
			buf_len,
			buf,
			out_len,
			compressed_data
			);

	if (!result) {
		free(compressed_data);
		*out_len = 0;
		return NULL;
	}

	return compressed_data;
}

char* gzip_compress(char* src, size_t src_len, size_t* dst_len)
{
	int compression_level  = Z_BEST_SPEED;
	unsigned long max_dst_len = compressBound((unsigned long)src_len) + 18;
	char *dst = malloc(max_dst_len);

	if (!dst) {
		return NULL;
	}

	z_stream stream;
	memset(&stream, 0, sizeof(stream));

	if (deflateInit2(&stream, compression_level, Z_DEFLATED,
				MAX_WBITS + 16,
				8, Z_DEFAULT_STRATEGY) != Z_OK) {
		free(dst);
		return NULL;
	}

	stream.next_in = (Bytef*)src;
	stream.avail_in = (uInt)src_len;
	stream.next_out = (Bytef*)dst;
	stream.avail_out = max_dst_len;

	int ret = deflate(&stream, Z_FINISH);

	if (ret != Z_STREAM_END) {
		deflateEnd(&stream);
		free(dst);
		return NULL;
	}

	*dst_len = stream.total_out;

	deflateEnd(&stream);
	return dst;
}

char* gzip_decompress(char* src, size_t src_len, size_t* dst_len)
{
	*dst_len = src_len * 5;
	char *dst = malloc(*dst_len);

	if (!dst) {
		return NULL;
	}

	z_stream stream;
	memset(&stream, 0, sizeof(stream));

	if (inflateInit2(&stream, MAX_WBITS + 16) != Z_OK) {
		free(dst);
		return NULL;
	}

	stream.next_in = (Bytef*)src;
	stream.avail_in = (uInt)src_len;
	stream.next_out = (Bytef*)dst;
	stream.avail_out = (uInt)(*dst_len);

	int ret = Z_OK;
	while (ret != Z_STREAM_END) {
		ret = inflate(&stream, Z_NO_FLUSH);

		if (ret == Z_OK) {
			size_t old_size = *dst_len;
			*dst_len *= 2;
			dst = realloc(dst, *dst_len);

			if (!dst) {
				inflateEnd(&stream);
				return NULL;
			}

			stream.next_out = (Bytef*)*dst + old_size;
			stream.avail_out = (uInt)(*dst_len - old_size);
		}
		else if (ret != Z_STREAM_END) {
			inflateEnd(&stream);
			free(dst);
			return NULL;
		}
	}

	*dst_len = stream.total_out;

	inflateEnd(&stream);
	return dst;
}

char* raw_deflate_compress(char* src, size_t src_len, size_t* dst_len)
{
	int level = Z_BEST_SPEED;
	z_stream strm;
	int ret;

	char *dst = NULL;
	*dst_len = 0;
	unsigned long max_len = compressBound((uLong)src_len);
	dst = (char*)malloc(max_len);
	if (!dst) 
		return NULL;

	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;

	ret = deflateInit2(&strm, level, Z_DEFLATED,
			-MAX_WBITS, 8, Z_DEFAULT_STRATEGY);
	if (ret != Z_OK) {
		free(dst);
		return NULL;
	}

	strm.next_in = src;
	strm.avail_in = (uInt)src_len;
	strm.next_out = dst;
	strm.avail_out = max_len;
	ret = deflate(&strm, Z_FINISH);

	if (ret == Z_STREAM_END) {
		*dst_len = strm.total_out;
		dst = (char*)realloc(dst, *dst_len);
	} else {
		free(dst);
		dst = NULL;
	}

	deflateEnd(&strm);
	if (ret == Z_STREAM_END)
		return dst;
	return NULL;
}

char* raw_deflate_decompress(char* src, size_t src_len, size_t* dst_len)
{
	z_stream strm;
	int ret;
	char *dst = NULL;
	*dst_len = 0;

	unsigned long estimated_len = (unsigned long)(src_len * 5);
	dst = (unsigned char*)malloc(estimated_len);
	if (!dst) 
		return NULL;

	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;
	strm.avail_in = 0;
	strm.next_in = Z_NULL;

	ret = inflateInit2(&strm, -MAX_WBITS);
	if (ret != Z_OK) {
		free(dst);
		return NULL;
	}

	strm.next_in = src;
	strm.avail_in = (uInt)src_len;
	strm.next_out = dst;
	strm.avail_out = estimated_len;

	do {
		ret = inflate(&strm, Z_NO_FLUSH);

		if (ret == Z_BUF_ERROR) {

			unsigned long old_len = estimated_len;
			estimated_len *= 2;
			dst = (unsigned char*)realloc(dst, estimated_len);
			if (!dst) {
				inflateEnd(&strm);
				return NULL;
			}

			strm.next_out = dst + old_len;
			strm.avail_out = estimated_len - old_len;
		}
		else if (ret < 0 && ret != Z_STREAM_END) {
			inflateEnd(&strm);
			free(dst);
			dst = NULL;
			return NULL;
		}

	} while (ret != Z_STREAM_END);

	*dst_len = strm.total_out;
	dst = (unsigned char*)realloc(dst, *dst_len);
	inflateEnd(&strm);

	return dst;
}


