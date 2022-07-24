#ifndef STORAGE_H
#define STORAGE_H

#include <string>
#include <map>
#include <vector>
#include <array>
#include "Server.h"
#include <iostream>
#include <sstream>
#include "Server.h"
#include "Utilities.h"
#include "Types.hpp"
#include "AES.hpp"
#include <unordered_map>
#include <iostream>
#include <fstream>
#include<string.h>
//#include <stxxl/vector>
//#include <stxxl/unordered_map>

using namespace std;

class Storage {
public:
    bool inMemoryStorage;
    bool profile = false;
    double cacheTime = 0;
    vector< unordered_map<prf_type, prf_type, PRFHasher> > data;
    //stxxl::unordered_map<prf_type, prf_type, PRFHasher, CompareLess, SUB_BLOCK_SIZE, SUB_BLOCKS_PER_BLOCK>** diskData;
    vector<string> filenames;
    int dataIndex;
    prf_type nullKey;
    string fileAddressPrefix;

public:
    int seekgCount = 0;
    int KEY_VALUE_SIZE = (2 * AES_KEY_SIZE + sizeof (long));
    Storage(bool inMemory, int dataIndex, string fileAddressPrefix, bool profile);
    bool setup(bool overwrite);
    void insert(int dataIndex, map<prf_type, prf_type> ciphers);
    vector<prf_type> getAllData(int dataIndex);
    void clear(int index);
    prf_type find(int index, prf_type mapKey, bool& found);
    virtual ~Storage();


};

#endif /* STORAGE_H */

