#include <iostream>
#include <string>
#include <vector>
#include "DES.h"
using namespace std;
vector<uint64_t> EncryptString(string& s,bitset<64> &key){
	DES des;
	const char* c = s.c_str();
	uint64_t num_64 = 0;
	vector<uint64_t> v;
	//把string以8个char为单位切分为unsignedlonglong
	for (int i = 0; i < s.size(); i+=8) {
		uint64_t res;
		num_64 = 0;
		for (int j = 0; j < 8 ; ++j) {
			num_64 = num_64<<8;
			if ((i + j) < s.size()) {
				num_64 += c[i + j];
			}
		}
		std::bitset<64> block(num_64);
		res = des.Encrypt(block,key).to_ullong();
		v.push_back(res);
	}
	return v;
}
string DecryptString(vector<uint64_t>& v, bitset<64> & key) {
	DES des;
	string s,seg;
	uint64_t num_64 = 0;
	for (int i = 0; i < v.size(); ++i) {
		seg = "";
		bitset<64> block(v[i]);
		uint64_t result;
		result = des.Decrypt(block,key).to_ullong();
		for (int i = 0; i < 8; ++i) {
			char c = result % 256;
			result = result >> 8;
			seg = c + seg;
		}
		s += seg;
	}
	return s;
}
int main()
{
	bitset<64> key;
	string plaintext = "Hello,World!";
	cout << "密文为：" << plaintext << endl;
	cout << "密钥为" << key << endl;
	vector<uint64_t> v = EncryptString(plaintext, key);
	cout << "加密后的密文:" << endl;
	for (int i = 0; i < v.size(); ++i) {
		bitset<64> block(v[i]);
		cout << block << endl;
	}
	cout << "解密结果" << std::endl;
	cout << DecryptString(v, key);
}
