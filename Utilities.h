#ifndef UTILITIES_H
#define UTILITIES_H
#include <string>
#include <map>
#include <vector>
#include <fstream>
#include <chrono>
#include <stdlib.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <math.h>
#include <set>
#include "Types.hpp"

#define SUB_BLOCK_SIZE 4096
#define SUB_BLOCKS_PER_BLOCK 4096

struct PRFHasher {

    std::size_t operator()(const prf_type &key) const {
        std::hash<byte_t> hasher;
        size_t result = 0;
        for (size_t i = 0; i < AES_KEY_SIZE; ++i) {
            result = (result << 1) ^ hasher(key[i]);
        }
        return result;
    }
};

struct CompareLess {

    bool operator()(const prf_type& a, const prf_type& b) const {
        for (int i = 0; i < AES_KEY_SIZE; i++) {
            if (a[i] > b[i]) {
                return false;
            } else if (a[i] < b[i]) {
                return true;
            }
        }
        //     return a < b; 
        return false;
    }

    static prf_type min_value() {
        prf_type result;
        for (int i = 0; i < AES_KEY_SIZE; i++) {
            result[i] = 0;
        }
        return result;
    }

    static prf_type max_value() {
        prf_type result;
        for (int i = 0; i < AES_KEY_SIZE; i++) {
            result[i] = 0xFF;
        }
        return result;
    }
};

template <typename T>
class TC {
public:
    uint N;
    uint K;
    std::vector<uint> Qs;
    std::vector<uint> delNumber;
    std::vector<std::string> keywords;
    std::vector<std::string> testKeywords;
    std::map<std::string, std::vector<T> > filePairs;
};

class Utilities {
private:
    static int parseLine(char* line);
public:
    Utilities();
    //        static std::string getSHA256(std::string input);
    //    static std::string encryptAndEncode(std::string input, unsigned char* key, unsigned char* iv);
    //    static std::string decodeAndDecrypt(std::string plaintext, unsigned char* key, unsigned char* iv);
    static unsigned char* sha256(char* input, int size);
    static std::string base64_encode(const char* bytes_to_encode, unsigned int in_len);
    static std::string base64_decode(std::string const& enc);
    static std::string XOR(std::string value, std::string key);
    static void startTimer(int id);
    static double stopTimer(int id);
    static std::map<int, std::chrono::time_point<std::chrono::high_resolution_clock> > m_begs;
    static std::map<std::string, std::ofstream*> handlers;
    static void logTime(std::string filename, std::string content);
    static void initializeLogging(std::string filename);
    static void finalizeLogging(std::string filename);
    static std::array<uint8_t, 16> convertToArray(std::string value);
    static int getMem();
    static double getTimeFromHist(int id);
    static int getBid(std::string srchIndex);
    static std::array<uint8_t, TMP_AES_KEY_SIZE> tmpencode(std::string keyword);
    static std::array<uint8_t, TMP_AES_KEY_SIZE> tmpencode(std::string keyword, unsigned char* curkey);
    static std::array<uint8_t, TMP_AES_KEY_SIZE> tmpencode(unsigned char* plaintext, unsigned char* curkey = NULL);
    static std::string tmpdecode(std::array<uint8_t, TMP_AES_KEY_SIZE> data, unsigned char* curkey = NULL);
    static unsigned char tmpkey[TMP_AES_KEY_SIZE], tmpiv[TMP_AES_KEY_SIZE];
    static std::array<uint8_t, AES_KEY_SIZE> encode(std::string keyword);
    static std::array<uint8_t, AES_KEY_SIZE> encode(std::string keyword, unsigned char* curkey);
    static std::array<uint8_t, AES_KEY_SIZE> encode(unsigned char* plaintext, unsigned char* curkey = NULL);
    static std::string decode(std::array<uint8_t, AES_KEY_SIZE> data, unsigned char* curkey = NULL);
    static unsigned char key[AES_KEY_SIZE], iv[AES_KEY_SIZE];
    static std::string testKeyword;
    static std::string rootAddress;
    static int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);
    static int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);
    static void handleErrors(void);
    static std::vector<std::string> splitData(const std::string& str, const std::string& delim);
    static void decode(std::array<uint8_t, AES_KEY_SIZE> ciphertext, std::array<uint8_t, AES_KEY_SIZE>& plaintext, unsigned char* curkey = NULL);
    static void tmpdecode(std::array<uint8_t, TMP_AES_KEY_SIZE> ciphertext, std::array<uint8_t, TMP_AES_KEY_SIZE>& plaintext, unsigned char* curkey = NULL);
    static std::array<uint8_t, TMP_AES_KEY_SIZE> tmpgeneratePRF(unsigned char* keyword, unsigned char* prfkey);
    static std::array<uint8_t, AES_KEY_SIZE> generatePRF(unsigned char* keyword, unsigned char* prfkey);

    template <typename T>
    static void readConfigFile(std::vector<TC<T> >& testCases, bool& inMemory, bool& overwrite) {
        std::ifstream infile;
        infile.open("crimes2.csv");
        std::string tmp;
        TC<T> testCase;
        int numOfLines = 6123275;
        testCase.N = numOfLines;
        testCase.K = 148;
        std::set<std::string> keywords;
        for (int i = 1; i <= numOfLines; i++) {
            getline(infile, tmp);
            testCase.filePairs[tmp].push_back(i);
            keywords.insert(tmp);
        }
        testCase.keywords.insert(testCase.keywords.end(), keywords.begin(), keywords.end());
        //        testCase.testKeywords.push_back("DOMESTIC");
        //        testCase.testKeywords.push_back("HUMANTRA");
        //        testCase.testKeywords.push_back("OTHERNAR");
        //        testCase.testKeywords.push_back("STALKING");
        //        testCase.testKeywords.push_back("LIQUORLA");
        //        testCase.testKeywords.push_back("ROBBERY");
        //
        //        testCase.Qs.push_back(1);
        //        testCase.Qs.push_back(22);
        //        testCase.Qs.push_back(111);
        //        testCase.Qs.push_back(2909);
        //        testCase.Qs.push_back(13546);
        //        testCase.Qs.push_back(229541);
        //
        //        testCase.delNumber.push_back(0);
        //        testCase.delNumber.push_back(2);
        //        testCase.delNumber.push_back(11);
        //        testCase.delNumber.push_back(290);
        //        testCase.delNumber.push_back(1354);
        //        testCase.delNumber.push_back(22954);


        //        testCase.testKeywords.push_back("CHURCH");
        //        testCase.testKeywords.push_back("HALLWAY");
        //        testCase.testKeywords.push_back("FIRESTAT");
        //        testCase.testKeywords.push_back("AIRPORTT");
        testCase.testKeywords.push_back("HOTELMOT");
        //        testCase.testKeywords.push_back("PARKINGL");

        //        testCase.Qs.push_back(4);
        //        testCase.Qs.push_back(78);
        //        testCase.Qs.push_back(907);
        //        testCase.Qs.push_back(5380);
        testCase.Qs.push_back(24698);
        //        testCase.Qs.push_back(175207);

        testCase.delNumber.push_back(4939);
        //        testCase.delNumber.push_back(0);
        //        testCase.delNumber.push_back(0);
        //        testCase.delNumber.push_back(0);
        //        testCase.delNumber.push_back(0);
        //        testCase.delNumber.push_back(0);


        infile.close();
        testCases.push_back(testCase);
    }

    template <typename T>
    static void readConfigFile(int argc, char** argv, std::string address, std::vector<TC<T> >& testCases, bool& inMemory, bool& overwrite) {
        /*
         * Config file structure (They should be sorted based on N)
         * 
         * Total Test Cases Number
         *      #for each test case
         *      N
         *      K
         *      query number
         *      #for each query 
         *          Q size
         *          delete number
         */
        std::ifstream infile;
        std::string tmp;

        //        if (argc > 1) {
        //            TC<T> testCase;
        //            testCase.N = std::stoi(argv[1]);
        //            testCase.K = std::stoi(argv[2]);
        //            testCase.Qs.push_back(std::stoi(argv[3]));
        //            testCase.delNumber.push_back(std::stoi(argv[4]));
        //            testCases.push_back(testCase);
        //        } else {
        infile.open(address);
        getline(infile, tmp);
        inMemory = (tmp == "true") ? true : false;
        getline(infile, tmp);
        overwrite = (tmp == "true") ? true : false;
        getline(infile, tmp);
        int totalTests = stoi(tmp);
        for (int i = 0; i < totalTests; i++) {
            TC<T> testCase;
            getline(infile, tmp);
            testCase.N = stoi(tmp);
            getline(infile, tmp);
            testCase.K = stoi(tmp);
            getline(infile, tmp);
            int qNum = stoi(tmp);
            for (int i = 0; i < qNum; i++) {
                getline(infile, tmp);
                testCase.Qs.push_back(stoi(tmp));
                getline(infile, tmp);
                testCase.delNumber.push_back(stoi(tmp));
            }
            testCases.push_back(testCase);
        }
        infile.close();
        //        }
    };

    template <typename T>
    static void generateTestCases(std::vector<TC<T> >& testCases, uint keywordLength, unsigned int seed) {
        char alphanum[] =
                "0123456789"
                "!@#$%^&*"
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz";

        srand(seed);
        uint totalKeywordSize = 0;
        uint totalPairNumber = 0;
        for (uint i = 0; i < testCases.size(); i++) {

            for (uint j = 0; j < testCases[i].K - totalKeywordSize; j++) {
                std::string str;
                for (uint k = 0; k < keywordLength; ++k) {
                    str += alphanum[rand() % (sizeof (alphanum) - 1)];
                }
                //                str="salam";
                testCases[i].keywords.push_back(str);
            }
            totalKeywordSize += testCases[i].keywords.size();

            for (uint j = 0; j < testCases[i].Qs.size(); j++) {
                testCases[i].testKeywords.push_back(testCases[i].keywords[j]);
            }


            for (uint j = 0; j < testCases[i].Qs.size(); j++) {
                std::vector<T> files;
                for (uint k = 0; k < testCases[i].Qs[j]; k++) {
                    files.push_back(k);
                    totalPairNumber++;
                }
                testCases[i].filePairs[testCases[i].testKeywords[j]] = files;
                files.clear();
            }
            uint totalCounter = totalPairNumber;
            uint reminderKeywords = testCases[i].keywords.size() - testCases[i].testKeywords.size();
            for (uint j = testCases[i].testKeywords.size(); j < testCases[i].keywords.size(); j++) {
                std::vector<T> files;
                for (uint k = 0; k < ceil((double) (testCases[i].N - totalCounter) / (double) reminderKeywords) && totalPairNumber < testCases[i].N; k++) {
                    int fileName = ((rand() % 10000000)) + 10000000;
                    files.push_back(fileName);
                    totalPairNumber++;
                }
                testCases[i].filePairs[testCases[i].keywords[j]] = files;
                files.clear();
            }
        }
    };
/*
    template <typename T>
    static void generateTestCases(std::vector<TC<T> >& testCases, uint keywordLength, unsigned int seed, std::vector<std::string> testKeywords) {
        char alphanum[] =
                "0123456789"
                "!@#$%^&*"
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz";

        srand(seed);
        uint totalKeywordSize = 0;
        uint totalPairNumber = 0;
        for (uint i = 0; i < testCases.size(); i++) {
            for (uint j = 0; j < testKeywords.size(); j++) {
                testCases[i].keywords.push_back(testKeywords[j]);
            }
            for (uint j = testKeywords.size(); j < testCases[i].K - totalKeywordSize; j++) {
                std::string str;
                for (uint k = 0; k < keywordLength; ++k) {
                    str += alphanum[rand() % (sizeof (alphanum) - 1)];
                }
                testCases[i].keywords.push_back(str);
            }
            totalKeywordSize += testCases[i].keywords.size();

            for (uint j = 0; j < testCases[i].Qs.size(); j++) {
                testCases[i].testKeywords.push_back(testCases[i].keywords[j]);
            }
            for (uint j = 0; j < testCases[i].Qs.size(); j++) {
                std::vector<T> files;
                for (uint k = 0; k < testCases[i].Qs[j]; k++) {
                    files.push_back(k);
                    totalPairNumber++;
                }
                testCases[i].filePairs[testCases[i].testKeywords[j]] = files;
                files.clear();
            }
            uint totalCounter = totalPairNumber;
            uint reminderKeywords = testCases[i].keywords.size() - testCases[i].testKeywords.size();
            for (uint j = testCases[i].testKeywords.size(); j < testCases[i].keywords.size(); j++) {
                std::vector<T> files;
                for (uint k = 0; k < ceil((double) (testCases[i].N - totalCounter) / (double) reminderKeywords) && totalPairNumber < testCases[i].N; k++) {
                    int fileName = ((rand() % 10000000)) + 10000000;
                    files.push_back(fileName);
                    totalPairNumber++;
                }
                testCases[i].filePairs[testCases[i].keywords[j]] = files;
                files.clear();
            }
        }
    };*/
    virtual ~Utilities();
};

#endif /* UTILITIES_H */

