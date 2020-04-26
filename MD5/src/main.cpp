#include <iostream>
#include "MD5.h"
using namespace std;
int main()
{
	MD5 md5;
	string plaintext = "Hello, World!";
	string ciphertext = md5.Encrypt(plaintext);
	cout << "密文为：" << plaintext << endl;
	cout << "加密后的密文:" << ciphertext << endl;
}
