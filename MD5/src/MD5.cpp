#include"MD5.h"
string MD5::Encrypt(string& plaintext) {
	this->plaintext = plaintext;
	resetBuffer();
	padding();
	for (int i = 0;i < total_len / 64;++i) { //每64个字节一块，进行加密
		run(i);
	}
	delete[] padding_text;
	return getResult();
};
//设置缓冲区
void MD5::resetBuffer() {
	buffer[0] = 0x67452301;
	buffer[1] = 0xefcdab89;
	buffer[2] = 0x98badcfe;
	buffer[3] = 0x10325476;
}

void MD5::padding() {
	unsigned long long len = (unsigned long long)plaintext.size() * 8; //位数
	int padding_len;
	if (len % 512 == 448) padding_len = 512;
	else padding_len = (960 - len % 512) % 512;
	padding_len /= 8; //字节数
	len /= 8;//字节数
	total_len = len+ padding_len + 8;//附加64位 即8个字节，总字节数
	padding_text = new unsigned char[total_len];
	for (int i = 0;i < total_len;++i) {//字节数
		if (i < len) padding_text[i] = plaintext[i];
		else {
			padding_text[i] = 0;
		}
	}
	padding_text[len] = 0x80; //10000....
	//末尾8个字节填充原消息
	len *= 8;//原消息位数
	for (int i = 0;i < 8;++i) {
		padding_text[total_len + i - 8] = (unsigned char)len;
		len = len >> 8;//移动一个字节
	}
}
string MD5::getResult(){ //将缓冲区结果输出为16进制string
	string res;
	for (int i = 0; i < 4; ++i) {
		unsigned int ui = buffer[i];
		for (int j = 0; j < 4; ++j) {
			unsigned char uc = ui;
			string hexs;
			for (int i = 1; i >= 0; --i) {
				char tmp = uc >> (i << 2)& 0x0F;
				if (tmp < 10)
					tmp += '0';
				else
					tmp += 'a' - 10;
				hexs += tmp;
			}
			ui >>= 8;
			res += hexs;
		}
	}
	return res;
}
void MD5::run(int blocknum) {
	unsigned int oldbuffer[4];
	//保留缓冲区内容
	for (int i = 0;i < 4;++i) oldbuffer[i] = buffer[i];
	for (int round = 0; round < 4; ++round) { //4轮压缩函数
		unsigned int tmp;
		for (int step = 0; step < 16; ++step) { //每轮16步
			//将当前处理的消息字转为32位 unsigned int
			int pos = blocknum * 64;
			if (round == 0) {
				pos += (step * 4);
			}
			else if (round == 1) {
				pos += ((step*5+1) % 16 * 4);
			}
			else if (round == 2) {
				pos += ((step*3+5) % 16 * 4);
			}
			else {
				pos += ((step*7) % 16 * 4);
			}
			unsigned int X = 0;
			//从begin开始将4个字节转换位unsigned int
			for (int j = pos+3; j >= pos; --j) {
				X |= padding_text[j];
				if (j != pos) X = X << 8;
			}
			if (round == 0) {
				tmp = F(buffer[0], buffer[1], buffer[2], buffer[3], X,  T_TABLE[round * 16 + step], LEFT_SHIFT_TABLE[round][step % 4]);
			}
			else if (round == 1) {
				tmp = G(buffer[0], buffer[1], buffer[2], buffer[3], X, T_TABLE[round * 16 + step], LEFT_SHIFT_TABLE[round][step % 4]);
			}
			else if (round == 2) {
				tmp = H(buffer[0], buffer[1], buffer[2], buffer[3],X, T_TABLE[round * 16 + step], LEFT_SHIFT_TABLE[round][step % 4]);
			}
			else if (round == 3) {
				tmp = I(buffer[0], buffer[1], buffer[2], buffer[3], X, T_TABLE[round * 16 + step], LEFT_SHIFT_TABLE[round][step % 4]);
			}
			//缓冲区交换
			buffer[0] = buffer[3];
			buffer[3] = buffer[2];
			buffer[2] = buffer[1];
			buffer[1] = tmp;
		}
	}
	// 缓冲区更新
	for (int i = 0; i < 4; ++i)
		buffer[i] += oldbuffer[i];
}

unsigned int MD5::F(unsigned int a, unsigned int b, unsigned int c, unsigned int d, unsigned int X, unsigned int T, unsigned int s) {
	unsigned int g = (b & c) | (~b & d);
	unsigned int res = a + g + X + T;
	return  ((res << s % 32) | (res >> (32 - s % 32))) + b;
}
unsigned int MD5::G(unsigned int a, unsigned int b, unsigned int c, unsigned int d, unsigned int X, unsigned int T, unsigned int s) {
	unsigned int g = (b & d) | (c & ~d);
	unsigned int res = a + g + X + T;
	return  ((res << s % 32) | (res >> (32 - s % 32))) + b;
}
unsigned int MD5::H(unsigned int a, unsigned int b, unsigned int c, unsigned int d, unsigned int X, unsigned int T, unsigned int s) {
	unsigned int g = b ^ c ^ d;
	unsigned int res = a + g + X + T;
	return  ((res << s % 32) | (res >> (32 - s % 32))) + b;
}
unsigned int MD5::I(unsigned int a, unsigned int b, unsigned int c, unsigned int d, unsigned int X, unsigned int T, unsigned int s) {
	unsigned int g = c ^ (b | ~d);
	unsigned int res = a + g + X + T;
	return  ((res << s % 32) | (res >> (32 - s % 32))) + b;
}
