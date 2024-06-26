#include "AmortizedBASServer.h"
#include <string.h>

AmortizedBASServer::AmortizedBASServer(int dataIndex, bool inMemory, bool overwrite, bool profile) {
    this->profile = profile;
    storage = new Storage(inMemory, dataIndex, Utilities::rootAddress, profile);
    storage->setup(overwrite);
}

AmortizedBASServer::~AmortizedBASServer() {
}

void AmortizedBASServer::storeCiphers(int dataIndex, map<prf_type, prf_type> ciphers) {
    storage->insert(dataIndex, ciphers);
}

vector<prf_type> AmortizedBASServer::search(int dataIndex, prf_type token) {
    vector<prf_type> results;
    storage->seekgCount = 0;
    bool exist = false;
    int cnt = 0;
    double serverSearchTime = 0;
    do {
        prf_type curToken = token, mapKey;
        unsigned char cntstr[AES_KEY_SIZE];
        memset(cntstr, 0, AES_KEY_SIZE);
        *(int*) (&(cntstr[AES_KEY_SIZE - 5])) = cnt;
        mapKey = Utilities::generatePRF(cntstr, curToken.data());
        bool found = false;
        if (profile) {
            Utilities::startTimer(45);
        }
        prf_type res = storage->find(dataIndex, mapKey, found);
        if (profile) {
            serverSearchTime += Utilities::stopTimer(45);
        }
        if (found) {
            results.push_back(res);
            exist = true;
            cnt++;
        } else {
            exist = false;
        }
    } while (exist);
    if (profile) {
        printf("server Search Time:%f number of SeekG:%d number of read bytes:%d\n", serverSearchTime, storage->seekgCount, storage->KEY_VALUE_SIZE * storage->seekgCount);
    }
    return results;
}

vector<prf_type> AmortizedBASServer::getAllData(int dataIndex) {
    return storage->getAllData(dataIndex);
}

void AmortizedBASServer::clear(int index) {
    storage->clear(index);
}
