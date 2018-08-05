#include <iostream>
#include <string>
#include <fstream>
#include <vector>

#include <openssl/dsa.h>
#include <openssl/sha.h>
#include <openssl/objects.h>
#include <openssl/engine.h>

// g++ dlcsign.cpp -lssl -lcrypto -o dlcsign

void readFile(
    std::vector<unsigned char> & data,
    const char * filename
) {
    data.clear();

    // open the file:
    std::streampos fileSize;
    std::ifstream file(filename, std::ios::binary);

    if (!file.is_open()) return;

    // get its size:
    file.seekg(0, std::ios::end);
    fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    // read the data:
    data.resize(fileSize);
    file.read((char*)&data[0], fileSize);
}

std::string fromHex(const std::string & hexed) {
    char h, l;
    std::string ret;
    int ie = hexed.length();
    ie -= (ie % 2 == 0) ? 1 : 2;
    for (int i = 0; i <= ie;) {
        h = hexed[i++];
        if (h >= 'A' && h <= 'F') { h = h - 'A' + 0x0a; } else
        if (h >= 'a' && h <= 'f') { h = h - 'a' + 0x0a; } else
        if (h >= '0' && h <= '9') { h -= '0'; } else {
            h = 0;
        }
        l = hexed[i++];
        if (l >= 'A' && l <= 'F') { l = l - 'A' + 0x0a; } else
        if (l >= 'a' && l <= 'f') { l = l - 'a' + 0x0a; } else
        if (l >= '0' && l <= '9') { l -= '0'; } else {
            l = 0;
        }
        ret.push_back((h << 4)|l);
    }
    return ret;
}

std::string toHex(const unsigned char * s, unsigned len, bool lower_case = false) {
    char h, l, c = lower_case ? 'a' : 'A';
    std::string ret;
    for (unsigned i = 0; i < len; ++i) {
        h = (0xf0 & s[i]) >> 4;
        if (h <= 9) { h += '0'; } else { h = h - 0x0a + c; }
        ret.push_back(h);
        l = 0x0f & s[i];
        if (l <= 9) { l += '0'; } else { l = l - 0x0a + c; }
        ret.push_back(l);
    }
    return ret;
} 

bool dlc_verify(
    const std::string & IndexFileCRC,
    const std::string & IndexFileSig
) {
    static DSA * dsa = NULL;
    if (!dsa) {
        std::vector<unsigned char> pub_key;
        readFile(pub_key, "pub.key");
        const unsigned char *p = pub_key.data();
        d2i_DSA_PUBKEY(&dsa, &p, pub_key.size());
    }
    if (!dsa) return false;

    unsigned char IndexFileCRC_sha1hash[20];
    SHA1((unsigned char*)IndexFileCRC.c_str(), IndexFileCRC.size(), IndexFileCRC_sha1hash);

    std::string IndexFileSig_bin = fromHex(IndexFileSig);
    int rc = DSA_verify(0, IndexFileCRC_sha1hash, sizeof(IndexFileCRC_sha1hash),
                        (unsigned char*) IndexFileSig_bin.c_str(), IndexFileSig_bin.size(),
                        dsa);
    return rc == 1;
}

bool dlc_sign(
    const std::string & IndexFileCRC,
    std::string & IndexFileSig
) {
    static DSA * dsa = NULL;
    if (!dsa) {
        std::vector<unsigned char> priv_key;
        readFile(priv_key, "priv.key");
        const unsigned char *p = priv_key.data();
        d2i_DSAPrivateKey(&dsa, &p, priv_key.size());
    }
    if (!dsa) return false;

    unsigned char hash[20];
    if (!SHA1((unsigned char*)IndexFileCRC.c_str(), IndexFileCRC.size(), hash)) {
        std::cerr << "ERR: SHA1 failed." << std::endl;
    } else {
        unsigned int sig_len = 0;
        unsigned char sig[256];
        if (!DSA_sign(NID_sha1, hash, sizeof(hash), sig, &sig_len, dsa)) {
            std::cerr << "ERR: DSA_sign failed." << std::endl;
        } else {
            IndexFileSig = toHex(sig, sig_len);
        }
    }
}

int main() {
    bool do_verify = true;
    std::string crc = "1148974934";
    std::string sign = "302c021425c3541a544de7d056b0b677810bb54d45b831ab021443163ffd73c4c34f0f2d5c7bc1778711d3a3abd4";
    if (do_verify) {
        std::cout << (dlc_verify(crc, sign) ? ""  : "NOT " ) << "verified" << std::endl;
    } else {
        if (dlc_sign(crc, sign)) {
            std::cout << sign << " for " << crc << std::endl;
        }
    }
}
