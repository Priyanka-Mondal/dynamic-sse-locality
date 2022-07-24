#ifndef ONECHOICESTORAGE_H
#define ONECHOICESTORAGE_H

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

class OneChoiceStorage {
public:
    bool inMemoryStorage;
    bool profile = false;
    double cacheTime = 0;
    vector<string> filenames;
    prf_type nullKey;
    string fileAddressPrefix = Utilities::rootAddress;
    long dataIndex;
    vector<long> numberOfBins;
    vector<long> sizeOfEachBin;
    vector< vector<prf_type> > data;
    //stxxl::VECTOR_GENERATOR< prf_type, 4, 8, 1 * 1024 * 1024, stxxl::RC, stxxl::lru >::result** diskData;

public:
    long readBytes = 0;
    long SeekG = 0;
    OneChoiceStorage(bool inMemory, long dataIndex, string fileAddressPrefix, bool profile);
    bool setup(bool overwrite);
    void insertAll(long dataIndex, vector<vector< prf_type> > ciphers, bool append = false, bool firstRun = false);
    vector<prf_type> getAllData(long dataIndex);
    void clear(long index);
    vector<prf_type> find(long index, prf_type mapKey, long cnt);
    virtual ~OneChoiceStorage();


};

#endif /* ONECHOICESTORAGE_H */

