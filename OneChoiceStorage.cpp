#include "OneChoiceStorage.h"

OneChoiceStorage::OneChoiceStorage(bool inMemory, long dataIndex, string fileAddressPrefix, bool profile) {
    this->inMemoryStorage = inMemory;
    this->fileAddressPrefix = fileAddressPrefix;
    this->dataIndex = dataIndex;
    this->profile = profile;
    memset(nullKey.data(), 0, AES_KEY_SIZE);
    for (long i = 0; i < dataIndex; i++) {
        long curNumberOfBins = i > 1 ? (long) ceil((float) pow(2, i) / (float) (log2(pow(2, i)) * log2(log2(pow(2, i))))) : 1;
        long curSizeOfEachBin = i > 1 ? (log2(pow(2, i)) * log2(log2(pow(2, i))))*3 : pow(2, i);
        numberOfBins.push_back(curNumberOfBins);
        sizeOfEachBin.push_back(curSizeOfEachBin);
        printf("OneChoiceStorage Level:%d number of Bins:%d size of bin:%d\n", i, curNumberOfBins, curSizeOfEachBin);
    }

}

bool OneChoiceStorage::setup(bool overwrite) {
    if (inMemoryStorage) {
        for (long i = 0; i < dataIndex; i++) {
            vector<prf_type> curData;
            data.push_back(curData);
        }
    } else {
        if (USE_XXL) {
					/*
            diskData = new stxxl::VECTOR_GENERATOR< prf_type, 4, 8, 1 * 1024 * 1024, stxxl::RC, stxxl::lru >::result*[dataIndex];
            for (long i = 0; i < dataIndex; i++) {
                diskData[i] = new stxxl::VECTOR_GENERATOR< prf_type, 4, 8, 1 * 1024 * 1024, stxxl::RC, stxxl::lru>::result();
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

                    long maxSize = numberOfBins[i] * sizeOfEachBin[i];
                    for (long j = 0; j < maxSize; j++) {
                        file.write((char*) nullKey.data(), AES_KEY_SIZE);
                    }
                    file.close();
                }
            }
        }
    }

}

void OneChoiceStorage::insertAll(long index, vector<vector< prf_type > > ciphers, bool append, bool firstRun) {
    if (inMemoryStorage) {
        for (auto item : ciphers) {
            data[index].insert(data[index].end(), item.begin(), item.end());
        }
    } else {
        if (USE_XXL) {/*
            for (auto item : ciphers) {
                for (auto pair : item) {
                    diskData[index]->push_back(pair);
                }

            }*/
        } else {
            if (append && !firstRun) {
                fstream file(filenames[index].c_str(), ios::binary | std::ios::app);
                if (file.fail()) {
                    cerr << "Error in insert: " << strerror(errno);
                }
                for (auto item : ciphers) {
                    for (auto pair : item) {
                        file.write((char*) pair.data(), AES_KEY_SIZE);
                    }
                }
                file.close();
            } else {
                fstream file(filenames[index].c_str(), ios::binary | ios::out);
                if (file.fail()) {
                    cerr << "Error in insert: " << strerror(errno);
                }
                for (auto item : ciphers) {
                    for (auto pair : item) {
                        file.write((char*) pair.data(), AES_KEY_SIZE);
                    }
                }
                file.close();
            }
        }
    }
}

vector<prf_type> OneChoiceStorage::getAllData(long index) {
    if (inMemoryStorage) {
        vector<prf_type> results;
        for (long i = 0; i < data[index].size(); i++) {
            results.push_back(data[index][i]);
        }
        return results;
    } else {
        if (USE_XXL) {/*
            vector<prf_type> results;
            for (long i = 0; i < diskData[index]->size(); i++) {
                results.push_back(diskData[index]->at(i));
            }
            return results;*/
        } else {
            vector<prf_type > results;
            fstream file(filenames[index].c_str(), ios::binary | ios::in | ios::ate);
            if (file.fail()) {
                cerr << "Error in read: " << strerror(errno);
            }
            if (DROP_CACHE) {
                Utilities::startTimer(113);
                system("echo 3 | sudo tee /proc/sys/vm/drop_caches");
                auto t = Utilities::stopTimer(113);
                printf("drop cache time:%f\n", t);
                cacheTime += t;
            }
            long size = file.tellg();
            file.seekg(0, ios::beg);
            char* keyValues = new char[size];
            file.read(keyValues, size);
            file.close();

            for (long i = 0; i < size / AES_KEY_SIZE; i++) {
                prf_type tmp;
                std::copy(keyValues + i*AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, tmp.begin());
                results.push_back(tmp);
            }

            delete keyValues;

            return results;
        }
    }
    //    printf("getAll Cache Time:%f\n",cacheTime);
}

void OneChoiceStorage::clear(long index) {
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
            long maxSize = numberOfBins[index] * sizeOfEachBin[index];
            for (long j = 0; j < maxSize; j++) {
                file.write((char*) nullKey.data(), AES_KEY_SIZE);
            }
            file.close();
        }
    }
}

OneChoiceStorage::~OneChoiceStorage() {
}

vector<prf_type> OneChoiceStorage::find(long index, prf_type mapKey, long cnt) {
    if (inMemoryStorage) {
        vector<prf_type> results;

        unsigned char* hash = Utilities::sha256((char*) mapKey.data(), AES_KEY_SIZE);
        if (cnt >= numberOfBins[index]) {
            return data[index];
        } else {
            long pos = (unsigned long) (*((long*) hash)) % numberOfBins[index];
            long readPos = pos * sizeOfEachBin[index];
            long fileLength = numberOfBins[index] * sizeOfEachBin[index];
            long remainder = fileLength - readPos;
            long totalReadLength = cnt * sizeOfEachBin[index];
            long readLength = 0;
            if (totalReadLength > remainder) {
                readLength = remainder;
                totalReadLength -= remainder;
            } else {
                readLength = totalReadLength;
                totalReadLength = 0;
            }
            for (long i = 0; i < readLength; i++) {
                results.push_back(data[index][i + readPos]);
            }
            if (totalReadLength > 0) {
                readLength = totalReadLength;
                for (long i = 0; i < readLength; i++) {
                    results.push_back(data[index][i]);
                }
            }
        }
        return results;
    } else {
        if (USE_XXL) {/*
            vector<prf_type> results;

            unsigned char* hash = Utilities::sha256((char*) mapKey.data(), AES_KEY_SIZE);
            if (cnt >= numberOfBins[index]) {
                for (long i = 0; i < numberOfBins[index] * sizeOfEachBin[index]; i++) {
                    results.push_back(diskData[index]->at(i));
                }
            } else {
                long pos = (unsigned long) (*((long*) hash)) % numberOfBins[index];
                long readPos = pos * sizeOfEachBin[index];
                long fileLength = numberOfBins[index] * sizeOfEachBin[index];
                long remainder = fileLength - readPos;
                long totalReadLength = cnt * sizeOfEachBin[index];
                long readLength = 0;
                if (totalReadLength > remainder) {
                    readLength = remainder;
                    totalReadLength -= remainder;
                } else {
                    readLength = totalReadLength;
                    totalReadLength = 0;
                }
                for (long i = 0; i < readLength; i++) {
                    results.push_back(diskData[index]->at(i + readPos));
                }
                if (totalReadLength > 0) {
                    readLength = totalReadLength;
                    for (long i = 0; i < readLength; i++) {
                        results.push_back(diskData[index]->at(i));
                    }
                }
            }
            return results;*/
        } else {
            vector<prf_type> results;

            std::fstream file(filenames[index].c_str(), ios::binary | ios::in);
            if (file.fail()) {
                cerr << "Error in read: " << strerror(errno);
            }
            unsigned char* hash = Utilities::sha256((char*) mapKey.data(), AES_KEY_SIZE);
            if (cnt >= numberOfBins[index]) {
                //read everything
                long fileLength = numberOfBins[index] * sizeOfEachBin[index] * AES_KEY_SIZE;
                char* keyValues = new char[fileLength];
                if (DROP_CACHE) {
                    Utilities::startTimer(113);
                    system("echo 3 | sudo tee /proc/sys/vm/drop_caches");
                    auto t = Utilities::stopTimer(113);
                    printf("drop cache time:%f\n", t);
                    cacheTime += t;
                }
                file.read(keyValues, fileLength);
                SeekG++;
                readBytes += fileLength;
                for (long i = 0; i < numberOfBins[index] * sizeOfEachBin[index]; i++) {
                    prf_type tmp;
                    std::copy(keyValues + i*AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, tmp.begin());
                    results.push_back(tmp);
                }
            } else {
                long pos = (unsigned long) (*((long*) hash)) % numberOfBins[index];
                long readPos = pos * AES_KEY_SIZE * sizeOfEachBin[index];
                long fileLength = numberOfBins[index] * sizeOfEachBin[index] * AES_KEY_SIZE;
                long remainder = fileLength - readPos;
                long totalReadLength = cnt * AES_KEY_SIZE * sizeOfEachBin[index];
                long readLength = 0;
                if (totalReadLength > remainder) {
                    readLength = remainder;
                    totalReadLength -= remainder;
                } else {
                    readLength = totalReadLength;
                    totalReadLength = 0;
                }
                if (DROP_CACHE) {
                    Utilities::startTimer(113);
                    system("echo 3 | sudo tee /proc/sys/vm/drop_caches");
                    auto t = Utilities::stopTimer(113);
                    printf("drop cache time:%f\n", t);
                    cacheTime += t;
                }
                file.seekg(readPos, ios::beg);
                SeekG++;
                char* keyValues = new char[readLength];
                file.read(keyValues, readLength);
                readBytes += readLength;
                for (long i = 0; i < readLength / AES_KEY_SIZE; i++) {
                    prf_type tmp;
                    std::copy(keyValues + i*AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, tmp.begin());
                    results.push_back(tmp);
                }
                if (totalReadLength > 0) {
                    readLength = totalReadLength;
                    if (DROP_CACHE) {
                        Utilities::startTimer(113);
                        system("echo 3 | sudo tee /proc/sys/vm/drop_caches");
                        auto t = Utilities::stopTimer(113);
                        printf("drop cache time:%f\n", t);
                        cacheTime += t;
                    }
                    file.seekg(0, ios::beg);
                    char* keyValues = new char[readLength];
                    file.read(keyValues, readLength);
                    readBytes += readLength;
                    SeekG++;
                    for (long i = 0; i < readLength / AES_KEY_SIZE; i++) {
                        prf_type tmp;
                        std::copy(keyValues + i*AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, tmp.begin());
                        results.push_back(tmp);
                    }

                    delete keyValues;
                }
            }
            file.close();
            return results;
        }
    }
    //    printf("Find Cache Time:%f\n", cacheTime);
}
