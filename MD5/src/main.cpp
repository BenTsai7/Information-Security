#include <iostream>
#include "MD5.h"
using namespace std;
int main()
{
	MD5 md5;
	string plaintext = "Hello, World!";
	string ciphertext = md5.Encrypt(plaintext);
	cout << "����Ϊ��" << plaintext << endl;
	cout << "���ܺ������:" << ciphertext << endl;
}
