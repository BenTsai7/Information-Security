#include"DES.h"
//初始置换表IP
static int IP_Table[64] = { 57,49,41,33,25,17,9,1,
					59,51,43,35,27,19,11,3,
					61,53,45,37,29,21,13,5,
					63,55,47,39,31,23,15,7,
					56,48,40,32,24,16,8,0,
					58,50,42,34,26,18,10,2,
					60,52,44,36,28,20,12,4,
					62,54,46,38,30,22,14,6 };
//逆初始置换表FP
static int FP_Table[64] = { 39,7,47,15,55,23,63,31,
					  38,6,46,14,54,22,62,30,
					  37,5,45,13,53,21,61,29,
					  36,4,44,12,52,20,60,28,
					  35,3,43,11,51,19,59,27,
					  34,2,42,10,50,18,58,26,
					  33,1,41,9,49,17,57,25,
					  32,0,40,8,48,16,56,24 };
//子密钥左移位数表
static int key_shifts[16] = { 1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1 };
//扩充置换表E   
static int E_Table[48] = { 31,0,1,2,3,4,
				   3,4,5,6,7,8,
				   7,8,9,10,11,12,
				   11,12,13,14,15,16,
				   15,16,17,18,19,20,
				   19,20,21,22,23,24,
				   23,24,25,26,27,28,
				   27,28,29,30,31,0 };

//置换函数P   
static int P_Table[32] = { 15,6,19,20,28,11,27,16,
						  0,14,22,25,4,17,30,9,
						  1,7,23,13,31,26,2,8,
						  18,12,29,5,21,10,3,24 };

//S盒   
static int S[8][4][16] = {
	//S1
	{{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
	{0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
	{4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
	{15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}},
	//S2   
	{{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
	{3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
	{0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
	{13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}},
	//S3   
	{{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
	{13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
	{13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
	{1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}},
	//S4   
	{{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
	{13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
	{10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
	{3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}},
	//S5   
	{{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
	{14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
	{4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
	{11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}},
	//S6   
	{{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
	{10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
	{9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
	{4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}},
	//S7   
	{{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
	{13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
	{1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
	{6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}},
	//S8   
	{{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
	{1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
	{7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
	{2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}}
};

//置换选择PC_1
static int PC_1[56] = { 56,48,40,32,24,16,8,
					   0,57,49,41,33,25,17,
					   9,1,58,50,42,34,26,
					   18,10,2,59,51,43,35,
					   62,54,46,38,30,22,14,
					   6,61,53,45,37,29,21,
					   13,5,60,52,44,36,28,
					   20,12,4,27,19,11,3,
						};
//置换选择PC_2
static int PC_2[48] = { 13,16,10,23,0,4,
					   2,27,14,5,20,9,
					   22,18,11,3,25,7,
					   15,6,26,19,12,1,
					   40,51,30,36,46,54,
					   29,39,50,44,32,47,
					   43,48,38,55,33,52,
					   45,41,49,35,28,31 };
static bitset<48> subkeys[16];

void DES::initial_subkeys_table(bitset<64> &key) {
	bitset<64> key1 = key;
	bitset<56> key2;
	bitset<48> key3;
	bitset<28> left_key, right_key;
	//PC_1置换
	for (int i = 0; i < 56; ++i)
		key2[55-i] = key1[63-PC_1[i]];
	//计算16轮的子密钥
	for (int i = 0; i < 16; ++i) {
		//将密钥分为左右两半
		for (int j = 28; j < 56; ++j)
			left_key[j - 28] = key2[j];
		for (int j = 0; j < 28; ++j)
			right_key[j] = key2[j];
		//左移
		if (key_shifts[i] == 1) {
			bitset<28> new_left_key(left_key.to_string().substr(1) + left_key.to_string()[0]),
				new_right_key(right_key.to_string().substr(1) + right_key.to_string()[0]);
			left_key = new_left_key;
			right_key = new_right_key;
		}
		else {
			bitset<28> new_left_key(left_key.to_string().substr(2)+ left_key.to_string().substr(0, 2)),
				new_right_key(right_key.to_string().substr(2)+ right_key.to_string().substr(0, 2));
			left_key = new_left_key;
			right_key = new_right_key;
		}
		//合成密钥
		for (int j = 28; j < 56; ++j)
			key2[j] = left_key[j - 28];
		for (int j = 0; j < 28; ++j)
			key2[j] = right_key[j];
		//PC_2置换
		for (int j = 0; j < 48; ++j)
			key3[47-j] = key2[55-PC_2[j]];
		subkeys[i] = key3;
	}
}
bitset<32> DES::Feistel(bitset<32> input, bitset<48> & subkey) {
	bitset<48> E_out;
	bitset<32> S_out;
	bitset<32> P_out;
	//E盒置换
	for (int i = 0; i < 48; ++i) E_out[47-i] = input[31-E_Table[i]];
	//与子密钥或与
	E_out = E_out ^ subkey;
	//S盒置换
	for (int i = 0; i < 8; ++i) {
		int leftpos = 47-i*6, rightpos = leftpos-5;
		int row = E_out[leftpos] * 2 + E_out[rightpos];
		int column = E_out[leftpos -1] * 8 + E_out[leftpos - 2] * 4 + E_out[leftpos-3] * 2 + E_out[leftpos - 4];
		bitset<4> Sbox_out(S[i][row][column]);
		for (int j = 0; j < 4; ++j) {
			S_out[31-i*4-j] = Sbox_out[3-j];
		}
	}
	//P盒置换
	for (int i = 0; i < 32; ++i) {
		P_out[31-i] = S_out[31-P_Table[i]];
	}
	return P_out;
}
bitset<64> DES::Encrypt(bitset<64> & plaintext,bitset<64> & key) {
	bitset<64> ciphertext;
	bitset<32> left, right;
	//IP置换
	for (int i = 0; i < 64; ++i) ciphertext[63-i] = plaintext[IP_Table[63-i]];
	//切割为左右32位
	for (int i = 32; i < 64; ++i)
		left[i - 32] = ciphertext[i];
	for (int i = 0; i < 32; ++i)
		right[i] = ciphertext[i];
	bitset<32> originright;
	//生成子密钥
	initial_subkeys_table(key);
	for (int i = 0; i < 16; ++i) {
		originright = right;
		//Feister网络
		right = Feistel(right, subkeys[i]) ^ left;
		left = originright;
	}
	for (int i = 0; i < 32; ++i)
		ciphertext[i] = left[i];
	for (int i = 32; i < 64; ++i)
		ciphertext[i] = right[i - 32];
	//FP置换
	bitset<64> tmp = ciphertext;
	for (int i = 0; i < 64; i++) {
		ciphertext[63-i] = tmp[63-FP_Table[i]];
	}
	return ciphertext;
}

bitset<64> DES::Decrypt(bitset<64> & ciphertext,bitset<64> & key) {
	bitset<64> plaintext;
	bitset<32> left, right;
	//IP置换
	for (int i = 0; i < 64; ++i) plaintext[63-i] = ciphertext[63-IP_Table[i]];
	//切割为左右32位
	for (int i = 32; i < 64; ++i)
		left[i - 32] = plaintext[i];
	for (int i = 0; i < 32; ++i)
		right[i] = plaintext[i];
	bitset<32> originright;
	initial_subkeys_table(key);
	for (int i = 0; i < 16; ++i) {
		originright = right;
		right = Feistel(right, subkeys[15 - i]) ^ left;
		left = originright;
	}
	for (int i = 0; i < 32; ++i)
		plaintext[i] = left[i];
	for (int i = 32; i < 64; ++i)
		plaintext[i] = right[i - 32];
	//FP置换
	bitset<64> tmp = plaintext;
	for (int i = 0; i < 64; i++) {
		plaintext[63-i] = tmp[FP_Table[63-i]];
	}
	return plaintext;
}