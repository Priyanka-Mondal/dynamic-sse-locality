#include "TwoChoiceWithOneChoiceStorage.h"
#include<string.h>

TwoChoiceWithOneChoiceStorage::TwoChoiceWithOneChoiceStorage(bool inMemory, long dataIndex, string fileAddressPrefix, bool profile) {
    this->inMemoryStorage = inMemory;
    this->fileAddressPrefix = fileAddressPrefix;
    this->dataIndex = dataIndex;
    this->profile = profile;
    memset(nullKey.data(), 0, AES_KEY_SIZE);
    for (long i = 0; i < dataIndex; i++) {
        long curNumberOfBins = i > 3 ? ((long) ceil((float) pow(2, i) / ((log2(log2(pow(2, i))))*(log2(log2(log2(pow(2, i)))))*(log2(log2(log2(pow(2, i)))))))) : pow(2, i);
        curNumberOfBins = pow(2, (long) ceil(log2(curNumberOfBins)));
        long curSizeOfEachBin = i > 3 ? ceil(2 * (log2(log2(pow(2, i))))*(log2(log2(log2(pow(2, i)))))*(log2(log2(log2(pow(2, i)))))) : 2;
        numberOfBins.push_back(curNumberOfBins);
        sizeOfEachBin.push_back(curSizeOfEachBin);
        printf("TwoChoiceWithOneChoiceStorage Level:%d number of Bins:%d size of bin:%d\n", i, curNumberOfBins, curSizeOfEachBin);
    }
}

bool TwoChoiceWithOneChoiceStorage::setup(bool overwrite) {
    if (inMemoryStorage) {
        for (long i = 0; i < dataIndex; i++) {
            vector<prf_type> curData;
            data.push_back(curData);
        }
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
                    file.write((char*) nullKey.data(), AES_KEY_SIZE);
                }
                file.close();
            }
        }
    }
}

void TwoChoiceWithOneChoiceStorage::insertStash(long index, vector<prf_type> ciphers) {
    string st = fileAddressPrefix + "STASH-" + to_string(index) + ".dat";
    fstream file(st, ios::binary | ios::out);
    if (file.fail()) {
        cout << "StashXX:" << index << endl;
        cerr << "(Error in Stash insert: " << strerror(errno) << ")" << endl;
    }
    for (auto item : ciphers) {
        unsigned char newRecord[AES_KEY_SIZE];
        memset(newRecord, 0, AES_KEY_SIZE);
        std::copy(item.begin(), item.end(), newRecord);
        file.write((char*) newRecord, AES_KEY_SIZE);
    }
    file.close();
}

vector<prf_type> TwoChoiceWithOneChoiceStorage::getStash(long index) {
    vector<prf_type> results;
    results.resize(0);
    string st = fileAddressPrefix + "STASH-" + to_string(index) + ".dat";
    fstream file(st, ios::binary | ios::in | ios::ate);
    if (file.fail()) {
        return results;
        cerr << "Error in read: " << strerror(errno);
    }
    long size = file.tellg();
    if (DROP_CACHE) {
        Utilities::startTimer(113);
        system("echo 3 | sudo tee /proc/sys/vm/drop_caches");
        auto t = Utilities::stopTimer(113);
        printf("drop cache time:%f\n", t);
        cacheTime += t;
    }
    file.seekg(0, ios::beg);
    SeekG++;
    char* keyValues = new char[size];
    file.read(keyValues, size);
    file.close();

    for (long i = 0; i < size / AES_KEY_SIZE; i++) {
        prf_type tmp;
        std::copy(keyValues + i*AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, tmp.begin());
        if (tmp != nullKey) {
            results.push_back(tmp);
        }
    }
    delete keyValues;
    return results;
}

void TwoChoiceWithOneChoiceStorage::insertAll(long index, vector<vector< prf_type > > ciphers, bool append, bool firstRun) {
    if (inMemoryStorage) {
        for (auto item : ciphers) {
            data[index].insert(data[index].end(), item.begin(), item.end());
        }
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

vector<prf_type> TwoChoiceWithOneChoiceStorage::getAllData(long index) {
    if (inMemoryStorage) {
        return data[index];
    } else {
        vector<prf_type> results;
        fstream file(filenames[index].c_str(), ios::binary | ios::in | ios::ate);
        if (file.fail()) {
            cerr << "Error in read: " << strerror(errno);
        }
        long size = file.tellg();
        if (DROP_CACHE) {
            Utilities::startTimer(113);
            system("echo 3 | sudo tee /proc/sys/vm/drop_caches");
            auto t = Utilities::stopTimer(113);
            printf("drop cache time:%f\n", t);
            cacheTime += t;
        }
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

void TwoChoiceWithOneChoiceStorage::clear(long index) {
    fstream file(filenames[index].c_str(), std::ios::binary | std::ofstream::out);
    if (file.fail())
        cerr << "Error: " << strerror(errno);
    long maxSize = numberOfBins[index] * sizeOfEachBin[index];
    for (long j = 0; j < maxSize; j++) {
        file.write((char*) nullKey.data(), AES_KEY_SIZE);
    }
    file.close();
}

TwoChoiceWithOneChoiceStorage::~TwoChoiceWithOneChoiceStorage() {
}

vector<prf_type> TwoChoiceWithOneChoiceStorage::find(long index, prf_type mapKey, long cnt) {
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
        long superBins = ceil((float) numberOfBins[index] / cnt);
        long pos = (unsigned long) (*((long*) hash)) % superBins; //numberOfBins[index];
        long readPos = pos * cnt * AES_KEY_SIZE * sizeOfEachBin[index];
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
            file.seekg(0, ios::beg);
            char* keyValues = new char[readLength];
            if (DROP_CACHE) {
                Utilities::startTimer(113);
                system("echo 3 | sudo tee /proc/sys/vm/drop_caches");
                auto t = Utilities::stopTimer(113);
                printf("drop cache time:%f\n", t);
                cacheTime += t;
            }
            file.read(keyValues, readLength);
            readBytes += readLength;
            SeekG++;
            for (long i = 0; i < readLength / AES_KEY_SIZE; i++) {
                prf_type tmp;
                std::copy(keyValues + i*AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, tmp.begin());
                results.push_back(tmp);
            }
        }
    }
    file.close();
    return results;
}

