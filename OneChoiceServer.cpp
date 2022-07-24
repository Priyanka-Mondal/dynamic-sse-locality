#include "OneChoiceServer.h"
#include <string.h>

OneChoiceServer::OneChoiceServer(long dataIndex, bool inMemory, bool overwrite, bool profile, bool storeKWCounter) {
    this->profile = profile;
    this->storeKWCounter = storeKWCounter;
    storage = new OneChoiceStorage(inMemory, dataIndex, Utilities::rootAddress, profile);
    storage->setup(overwrite);
    if (storeKWCounter) {
        keywordCounters = new Storage(inMemory, dataIndex, Utilities::rootAddress + "keyword-", profile);
        keywordCounters->setup(overwrite);
    }
}

OneChoiceServer::~OneChoiceServer() {
}

void OneChoiceServer::storeKeywordCounters(long dataIndex, map<prf_type, prf_type> kwCounters) {
    keywordCounters->insert(dataIndex, kwCounters);
}

void OneChoiceServer::storeCiphers(long dataIndex, vector<vector<prf_type> > ciphers) {
    storage->insertAll(dataIndex, ciphers, false, true);
}

void OneChoiceServer::storeCiphers(long dataIndex, vector<vector<prf_type> > ciphers, map<prf_type, prf_type> kwCounters) {
    storage->insertAll(dataIndex, ciphers);
    keywordCounters->insert(dataIndex, kwCounters);
}

void OneChoiceServer::storeCiphers(long dataIndex, vector<vector<prf_type> > ciphers, bool firstRun) {
    storage->insertAll(dataIndex, ciphers, true, firstRun);
}

vector<prf_type> OneChoiceServer::search(long dataIndex, prf_type token, long& keywordCnt) {
    if (storeKWCounter) {
        keywordCounters->seekgCount = 0;
    }
    storage->readBytes = 0;
    double keywordCounterTime = 0, serverSearchTime = 0;
    if (profile) {
        Utilities::startTimer(35);
    }
    prf_type curToken = token;
    unsigned char cntstr[AES_KEY_SIZE];
    memset(cntstr, 0, AES_KEY_SIZE);
    *(int*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
    prf_type keywordMapKey = Utilities::generatePRF(cntstr, curToken.data());
    bool found = false;
    prf_type res;
    if (storeKWCounter) {
        res = keywordCounters->find(dataIndex, keywordMapKey, found);
    }
    if (profile && storeKWCounter) {
        keywordCounterTime = Utilities::stopTimer(35);
        printf("keyword counter Search Time:%f number of SeekG:%d number of read bytes:%d\n", keywordCounterTime, keywordCounters->seekgCount, keywordCounters->KEY_VALUE_SIZE * keywordCounters->seekgCount);
        Utilities::startTimer(45);
    }

    vector<prf_type> result;
    if (storeKWCounter) {
        if (found) {
            prf_type plaintext;
            Utilities::decode(res, plaintext, curToken.data());
            keywordCnt = *(long*) (&(plaintext[0]));
        }
    }
    result = storage->find(dataIndex, keywordMapKey, keywordCnt);
    if (profile) {
        serverSearchTime = Utilities::stopTimer(45);
        printf("server Search Time:%f number of SeekG:%d number of read bytes:%d\n", serverSearchTime, storage->SeekG, storage->readBytes);
    }
    return result;
}

vector<prf_type > OneChoiceServer::getAllData(long dataIndex) {
    return storage->getAllData(dataIndex);
}

void OneChoiceServer::clear(long index) {
    storage->clear(index);
    if (storeKWCounter) {
        keywordCounters->clear(index);
    }
}
