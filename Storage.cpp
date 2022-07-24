#include "Storage.h"

Storage::Storage(bool inMemory, int dataIndex, string fileAddressPrefix, bool profile) {
    this->inMemoryStorage = inMemory;
    this->fileAddressPrefix = fileAddressPrefix;
    this->dataIndex = dataIndex;
    this->profile = profile;
    memset(nullKey.data(), 0, AES_KEY_SIZE);

}

bool Storage::setup(bool overwrite) {
    if (inMemoryStorage) {
        for (int i = 0; i < dataIndex; i++) {
            unordered_map<prf_type, prf_type, PRFHasher> curData;
            data.push_back(curData);
        }
    } else {
        if (USE_XXL) {
        /*    diskData = new stxxl::unordered_map<prf_type, prf_type, PRFHasher, CompareLess, SUB_BLOCK_SIZE, SUB_BLOCKS_PER_BLOCK>*[dataIndex];
            for (int i = 0; i < dataIndex; i++) {
                diskData[i] = new stxxl::unordered_map<prf_type, prf_type, PRFHasher, CompareLess, SUB_BLOCK_SIZE, SUB_BLOCKS_PER_BLOCK>();
            }*/
        } else {
            for (long i = 0; i < dataIndex; i++) {
                string filename = fileAddressPrefix + "MAP-" + to_string(i) + ".dat";
                filenames.push_back(filename);
                fstream testfile(filename.c_str(), std::ofstream::in);
                if (testfile.fail() || overwrite) {
                    testfile.close();

                    fstream file(filename.c_str(), std::ofstream::out);
                    if (file.fail()) {
                        cerr << "Error: " << strerror(errno);
                    }
                    long maxSize = pow(2, i);
                    long nextPtr = 0;
                    for (int j = 0; j < maxSize; j++) {
                        file.write((char*) nullKey.data(), AES_KEY_SIZE);
                        file.write((char*) nullKey.data(), AES_KEY_SIZE);
                        file.write((char*) &nextPtr, sizeof (long));
                    }
                    //                file.write((char*) &nextPtr, sizeof (int));
                    file.close();
                }
            }
        }

    }
}

void Storage::insert(int dataIndex, map<prf_type, prf_type> ciphers) {
    if (inMemoryStorage) {
        data[dataIndex].insert(ciphers.begin(), ciphers.end());
    } else {
        if (USE_XXL) {/*
            for (auto item : ciphers) {
                diskData[dataIndex]->insert(std::make_pair(item.first, item.second));
            }*/
        } else {
            long maxSize = pow(2, dataIndex);
            for (auto item : ciphers) {
                unsigned char newRecord[KEY_VALUE_SIZE];
                memset(newRecord, 0, KEY_VALUE_SIZE);
                std::copy(item.first.begin(), item.first.end(), newRecord);
                std::copy(item.second.begin(), item.second.end(), newRecord + AES_KEY_SIZE);

                unsigned char* hash = Utilities::sha256((char*) item.first.data(), AES_KEY_SIZE);
                long pos = (unsigned long) (*((long*) hash)) % maxSize;

                fstream file(filenames[dataIndex].c_str(), ios::binary | ios::in | ios::out | ios::ate);
                if (file.fail()) {
                    cerr << "Error in insert: " << strerror(errno);
                }
                long tmpNextPos = file.tellp();
                file.seekg(pos * KEY_VALUE_SIZE, ios::beg);


                char chainHead[KEY_VALUE_SIZE];
                file.read(chainHead, KEY_VALUE_SIZE);
                long nextPos = 0;

                prf_type tmp;
                std::copy(chainHead, chainHead + AES_KEY_SIZE, tmp.begin());

                if (tmp != nullKey) {
                    nextPos = tmpNextPos;
                    file.seekp(nextPos, ios::beg);
                    file.write(chainHead, KEY_VALUE_SIZE);
                }

                memcpy(&newRecord[2 * AES_KEY_SIZE], &nextPos, sizeof (long));
                //                for (int i = 0; i < 36; i++) {
                //                    printf("%X ", newRecord[i]);
                //                }
                //                printf("\n");


                file.seekp(pos* KEY_VALUE_SIZE, ios::beg);
                file.write((char*) newRecord, KEY_VALUE_SIZE);
                file.close();
            }

        }
    }
}

vector<prf_type> Storage::getAllData(int dataIndex) {
    vector<prf_type> results;
    if (inMemoryStorage) {
        for (auto item : data[dataIndex]) {
            results.push_back(item.second);
        }
    } else {
        if (USE_XXL) {/*
            for (auto item : (*diskData[dataIndex])) {
                results.push_back(item.second);
            }*/
        } else {
            fstream file(filenames[dataIndex].c_str(), ios::binary | ios::in | ios::ate);
            if (file.fail()) {
                cerr << "Error in read: " << strerror(errno);
            }
            int size = file.tellg();
            if (DROP_CACHE) {
                Utilities::startTimer(113);
                system("echo 3 | sudo tee /proc/sys/vm/drop_caches");
                auto t = Utilities::stopTimer(113);
                printf("drop cache time:%f\n", t);
                cacheTime += t;
            }
            file.seekg(0, ios::beg);
            char* keyValue = new char[size];
            file.read(keyValue, size);

            for (int i = 0; i < size / KEY_VALUE_SIZE; i++) {
                prf_type tmp, restmp;
                std::copy(keyValue + i*KEY_VALUE_SIZE, keyValue + i * KEY_VALUE_SIZE + AES_KEY_SIZE, tmp.begin());
                std::copy(keyValue + i * KEY_VALUE_SIZE + AES_KEY_SIZE, keyValue + i * KEY_VALUE_SIZE + AES_KEY_SIZE + AES_KEY_SIZE, restmp.begin());
                if (tmp != nullKey) {
                    results.push_back(restmp);
                }
            }

            file.close();
            delete keyValue;
            //            printf("Storage getalldata Cache time:%f\n",cacheTime);
            return results;
        }
    }
    return results;
}

void Storage::clear(int index) {
    if (inMemoryStorage) {
        data[index].clear();
    } else {
        if (USE_XXL) {/*
            diskData[index]->clear();*/
        } else {
            fstream file(filenames[index].c_str(), std::ios::binary | std::ofstream::out);
            if (file.fail()) {
                cerr << "Error: " << strerror(errno);
            }
            int maxSize = pow(2, index);
            long nextPtr = 0;
            for (int j = 0; j < maxSize; j++) {
                file.write((char*) nullKey.data(), AES_KEY_SIZE);
                file.write((char*) nullKey.data(), AES_KEY_SIZE);
                file.write((char*) &nextPtr, sizeof (long));
            }
            file.close();
        }
    }
}

Storage::~Storage() {
}

prf_type Storage::find(int index, prf_type mapKey, bool& found) {
    prf_type result;
    if (inMemoryStorage) {
        if (data[index].count(mapKey) == 0) {
            found = false;
            return result;
        } else {
            found = true;
            return data[index][mapKey];
        }
    } else {
        if (USE_XXL) {/*
            if (diskData[index]->count(mapKey) == 0) {
                found = false;
                return result;
            } else {
                found = true;
                return (*diskData[index])[mapKey];
            }*/
        } else {

            std::fstream file(filenames[index].c_str(), ios::binary | ios::in);
            if (file.fail()) {
                cerr << "Error in read: " << strerror(errno);
            }
            unsigned char* hash = Utilities::sha256((char*) mapKey.data(), AES_KEY_SIZE);
            long maxSize = pow(2, index);
            long readPos = (unsigned long) (*((long*) hash)) % maxSize;
            readPos = readPos*KEY_VALUE_SIZE;

            do {
                if (DROP_CACHE) {
                    Utilities::startTimer(113);
                    system("echo 3 | sudo tee /proc/sys/vm/drop_caches");
                    auto t = Utilities::stopTimer(113);
                    printf("drop cache time:%f\n", t);
                    cacheTime += t;
                }
                file.seekg(readPos, ios::beg);
                if (profile) {
                    seekgCount++;
                }
                char chain[KEY_VALUE_SIZE];
                file.read(chain, KEY_VALUE_SIZE);
                prf_type tmp, restmp;
                std::copy(chain, chain + AES_KEY_SIZE, tmp.begin());
                std::copy(chain + AES_KEY_SIZE, chain + (2 * AES_KEY_SIZE), restmp.begin());
                memcpy(&readPos, chain + 2 * AES_KEY_SIZE, sizeof (long));
                if (tmp == mapKey) {
                    file.close();
                    found = true;
                    //                    printf("Storage find cache time:%f\n", cacheTime);
                    return restmp;
                }

            } while (readPos != 0);
            file.close();
            found = false;
            //            printf("Storage find Cache Time:%f\n", cacheTime);
            return nullKey;
        }
    }
}
