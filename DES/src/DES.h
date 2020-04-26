#include<bitset>
using namespace std;

class DES {
private:
	void initial_subkeys_table(bitset<64> & key);
	bitset<32> Feistel(bitset<32> input, bitset<48> & subkey);
public:
	bitset<64> Encrypt(bitset<64> & plaintext,bitset<64> & key);
	bitset<64> Decrypt(bitset<64> & ciphertext,bitset<64> & key);
};