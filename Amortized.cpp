#include "Amortized.h"
#include "OneChoiceClient.h"
#include "TwoChoicePPwithStashClient.h"
#include "TwoChoiceWithOneChoiceClient.h"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

using namespace std;

Amortized::Amortized(int N, bool inMemory, bool overwrite) {
    //    L = new AmortizedBASClient(ceil(log2(N)), inMemory, overwrite, profile);
        //L = new OneChoiceClient(ceil(log2(N)), inMemory, overwrite, profile);
    //  L = new TwoChoicePPwithStashClient(ceil(log2(N)), inMemory, overwrite, profile);
    L = new TwoChoiceWithOneChoiceClient(ceil(log2(N)), inMemory, overwrite, profile);
    for (int i = 0; i < ceil(log2(N)); i++) {
        keys.push_back(NULL);
    }
    for (int i = 0; i < ceil(log2(N)); i++) {
        data.push_back(unordered_map<string, vector<prf_type> >());
    }
    if (!overwrite) {
        fstream file(Utilities::rootAddress + "existStatus.txt", std::ofstream::in);
        if (file.fail()) {
            file.close();
            return;
        }
        for (unsigned int i = localSize; i < L->exist.size(); i++) {
            string data;
            getline(file, data);
            if (data == "true") {
                L->exist[i] = true;
                unsigned char* newKey = new unsigned char[AES_KEY_SIZE];
                memset(newKey, 0, AES_KEY_SIZE);
                keys[i] = newKey;
            } else {
                L->exist[i] = false;
            }
        }

        file.close();
    }
}

Amortized::~Amortized() {
    fstream file(Utilities::rootAddress + "existStatus.txt", std::ofstream::out);
    if (file.fail()) {
        cerr << "Error: " << strerror(errno);
    }
    for (unsigned int i = localSize; i < L->exist.size(); i++) {
        if (L->exist[i]) {
            file << "true" << endl;
        } else {
            file << "false" << endl;
        }
    }
    file.close();
}

void Amortized::update(OP op, string keyword, int ind, bool setup) {
    totalUpdateCommSize = 0;
    L->totalCommunication = 0;
    int rm0 = log2((~updateCounter & (updateCounter + 1)));
    updateCounter++;
    unordered_map<string, vector<prf_type> > previousData;
    unordered_map<string, vector<tmp_prf_type> > setupPreviousData;

    if (setup) {
        for (int i = 0; i < min(rm0, tmpLocalSize); i++) {
            for (auto item : setupData[i]) {
                if (setupPreviousData.count(item.first) == 0) {
                    setupPreviousData[item.first] = vector<tmp_prf_type>();
                }
                setupPreviousData[item.first].insert(setupPreviousData[item.first].end(), item.second.begin(), item.second.end());
            }
            setupData[i].clear();
        }
    } else {
        for (int i = 0; i < min(rm0, localSize); i++) {
            for (auto item : data[i]) {
                if (previousData.count(item.first) == 0) {
                    previousData[item.first] = vector<prf_type>();
                }
                previousData[item.first].insert(previousData[item.first].end(), item.second.begin(), item.second.end());
            }
            data[i].clear();
        }
    }

    if (!setup) {
        for (int i = localSize; i < rm0; i++) {
            vector<prf_type> curData = L->getAllData(i, keys[i]);
            for (auto item : curData) {
                string curKeyword((char*) item.data());
                if (previousData.count(curKeyword) == 0) {
                    previousData[curKeyword] = vector < prf_type>();
                }
                previousData[curKeyword].push_back(item);
            }

            L->destry(i);
            delete keys[i];
            keys[i] = NULL;
        }
    }

    if (setup) {
        tmp_prf_type value;
        std::fill(value.begin(), value.end(), 0);
        std::copy(keyword.begin(), keyword.end(), value.begin());
        *(int*) (&(value.data()[TMP_AES_KEY_SIZE - 5])) = ind;
        value.data()[TMP_AES_KEY_SIZE - 6] = (byte) (op == OP::INS ? 0 : 1);

        if (setupPreviousData.count(keyword) == 0) {
            setupPreviousData[keyword] = vector<tmp_prf_type>();
        }
        setupPreviousData[keyword].push_back(value);
        setupData[rm0].insert(setupPreviousData.begin(), setupPreviousData.end());

    } else {
        prf_type value;
        std::fill(value.begin(), value.end(), 0);
        std::copy(keyword.begin(), keyword.end(), value.begin());
        *(int*) (&(value.data()[AES_KEY_SIZE - 5])) = ind;
        value.data()[AES_KEY_SIZE - 6] = (byte) (op == OP::INS ? 0 : 1);

        if (previousData.count(keyword) == 0) {
            previousData[keyword] = vector<prf_type>();
        }
        previousData[keyword].push_back(value);
        if (rm0 < localSize) {
            data[rm0].insert(previousData.begin(), previousData.end());
        } else {
            unsigned char* newKey = new unsigned char[AES_KEY_SIZE];
            memset(newKey, 0, AES_KEY_SIZE);
            keys[rm0] = newKey;
            L->setup(rm0, previousData, newKey);
            totalUpdateCommSize += L->totalCommunication;
        }
    }
}

vector<int> Amortized::search(string keyword) {
    L->TotalCacheTime = 0;
    totalSearchCommSize = 0;
    if (profile) {
        Utilities::startTimer(33);
    }
    L->totalCommunication = 0;
    vector<int> finalRes;
    vector<prf_type> encIndexes;
    int s = data.size();
    for (int i = 0; i < min(localSize, s); i++) {
        if (data[i][keyword].size() > 0) {
            encIndexes.insert(encIndexes.end(), data[i][keyword].begin(), data[i][keyword].end());
        }
    }
    for (unsigned int i = localSize; i < L->exist.size(); i++) {
        if (L->exist[i]) {
            if (profile) {
                printf("level %d:\n", i);
            }
            auto tmpRes = L->search(i, keyword, keys[i]);
            encIndexes.insert(encIndexes.end(), tmpRes.begin(), tmpRes.end());
        }
    }

    double filterationTime = 0;
    double searchTime = 0;
    if (profile) {
        searchTime = Utilities::stopTimer(33);
        printf("Amortized Search time:%f\n", searchTime);
        Utilities::startTimer(99);
    }
    map<int, int> remove;
    for (auto i = encIndexes.begin(); i != encIndexes.end(); i++) {
        prf_type decodedString = *i;
        int plaintext = *(int*) (&(decodedString.data()[AES_KEY_SIZE - 5]));
        remove[plaintext] += (2 * ((byte) decodedString.data()[AES_KEY_SIZE - 6]) - 1);
    }
		cout <<"remove:"<<remove.size()<<endl;
    for (auto const& cur : remove) {
        if (cur.second < 0) {
            finalRes.emplace_back(cur.first);
        }
    }
    if (profile) {
        filterationTime = Utilities::stopTimer(99);
        printf("filteration time:%f\n", filterationTime);
        printf("total drop cache command time for Storage:%f\n", L->TotalCacheTime);
    }
    totalSearchCommSize += L->totalCommunication;

    return finalRes;
}

prf_type Amortized::bitwiseXOR(int input1, int op, prf_type input2) {
    prf_type result;
    result[3] = input2[3] ^ ((input1 >> 24) & 0xFF);
    result[2] = input2[2] ^ ((input1 >> 16) & 0xFF);
    result[1] = input2[1] ^ ((input1 >> 8) & 0xFF);
    result[0] = input2[0] ^ (input1 & 0xFF);
    result[4] = input2[4] ^ (op & 0xFF);
    for (int i = 5; i < AES_KEY_SIZE; i++) {
        result[i] = (rand() % 255) ^ input2[i];
    }
    return result;
}

prf_type Amortized::bitwiseXOR(prf_type input1, prf_type input2) {
    prf_type result;
    for (unsigned int i = 0; i < input2.size(); i++) {
        result[i] = input1.at(i) ^ input2[i];
    }
    return result;
}

double Amortized::getTotalSearchCommSize() const {
    return totalSearchCommSize;
}

double Amortized::getTotalUpdateCommSize() const {
    return totalUpdateCommSize;
}

void Amortized::endSetup() {
    for (int i = 0; i < tmpLocalSize; i++) {
        if (setupData[i].size() > 0) {
            unsigned char* newKey = new unsigned char[AES_KEY_SIZE];
            memset(newKey, 0, AES_KEY_SIZE);
            L->setup2(i, setupData[i], newKey);
        }
    }
    setup = false;
}

void Amortized::beginSetup() {
    setup = true;
    tmpLocalSize = data.size();
    for (int i = 0; i < tmpLocalSize; i++) {
        setupData.push_back(unordered_map<string, vector<tmp_prf_type> >());
    }
}
