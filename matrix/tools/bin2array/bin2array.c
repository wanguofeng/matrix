#include <stdio.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#define USAGE "Usage: %s [firmware.bin] [firmware.c] [firmware.h] [version]\n\n"

int htoi(char s[])  
{  
	int i;  
	int n = 0;  
	
	if (s[0] == '0' && (s[1]=='x' || s[1]=='X'))
		i = 2;
	else
		i = 0;

	for (; (s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'z') || (s[i] >='A' && s[i] <= 'Z');++i) {
		if (tolower(s[i]) > '9') {
			n = 16 * n + (10 + tolower(s[i]) - 'a');  
		} else {
			n = 16 * n + (tolower(s[i]) - '0');  
		}
	}

	return n;  
}  

int get_file_size(char* filename) 
{ 
	struct stat statbuf; 
	stat(filename,&statbuf); 
	int size=statbuf.st_size;  //以字节为单位的文件容量
	return size; 
}

int main(int argc, char * argv[])
{
	int bin_fd = 0, c_fd = 0, h_fd = 0;
	char * bin_file_name = NULL;
	char * c_file_name = NULL;
	char * h_file_name = NULL;
	int version = 0;

	int bin_file_length = 0;
	char str[256] = {0x00};
	unsigned char payload[16] = {0x00};
	int payload_len = 16;

	if (argc < 5) {
		printf(USAGE, argv[0]);
		return -1;
	}

	bin_file_name = argv[1];
	c_file_name = argv[2];
	h_file_name = argv[3];
	version = htoi(argv[4]);

	bin_file_length = get_file_size(bin_file_name);
	if (bin_file_length == 0) {
		printf("%s is not exist!!!\n", bin_file_name);
		return -1;
	}

	bin_fd = open(bin_file_name, O_RDONLY);
	if (bin_fd <= 0) {
		printf("%s open failed!!!\n", bin_file_name);
		return -2;
	}

	c_fd = open(c_file_name, O_WRONLY|O_CREAT|S_IRUSR, 0666);
	if (c_fd <= 0) {
		printf("%s open failed!!!\n", c_file_name);
		return -3;
	}
	
	h_fd = open(h_file_name, O_WRONLY|O_CREAT|S_IRUSR, 0666);
	if (h_fd <= 0) {
		printf("%s open failed!!!\n", h_file_name);
		return -3;
	}
	memset(str,0x00, sizeof(str));
	sprintf(str, "#ifndef _FIRMWARE_H_\n#define _FIRMWARE_H_\n#include <sys/util.h>\nextern uint8_t telink_dfu_firmware_bin[%d];\nextern uint16_t firmware_version;\n#endif\n\n", bin_file_length);
	if (-1 == write(h_fd, str, strlen(str))) {
		printf("write file error.\n");
		return -3;	
	}

	memset(str,0x00, sizeof(str));
	sprintf(str, "#include <sys/util.h>\n#include\"firmware.h\"\n\nuint16_t firmware_version = 0x%04x;\nuint8_t telink_dfu_firmware_bin[%d] = {\n", version, bin_file_length);
	if (-1 == write(c_fd, str, strlen(str))) {
		printf("write file error.\n");
		return -3;	
	}
	
	while (bin_file_length > 0) {
		int i = 0, j= 0;
		int read_num = read(bin_fd, payload, payload_len);

		if (read_num == -1){
			printf("read file error.\n");
			return -4;
		}

		bin_file_length -= read_num;
		for (i = 0; i < read_num; i++) {
			char str1[20] = {0x00};
			if (i == 0)
				sprintf(str1, "0x%02x, ", payload[i]);
			else if (i == read_num - 1)
				sprintf(str1, "0x%02x,\n", payload[i]);
			else
				sprintf(str1, "0x%02x, ", payload[i]);

			if ( -1 == write(c_fd, str1, strlen(str1))) {
				printf("write file error.\n");
				return -5;
			}
		}

		memset(payload, 0x00, sizeof(payload));
		memset(str, 0x00, sizeof(str));
	}

	sprintf(str, "};\n");
	if (-1 == write(c_fd, str, strlen(str))) {
		printf("write file error.\n");
		return -3;	
	}


	close(bin_fd);
	close(c_fd);
	close(h_fd);

}
