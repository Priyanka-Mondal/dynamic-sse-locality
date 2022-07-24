#include "DeAmortizedSDdNoOMAP.h"
//#include "Amortized.h"
#include "Utilities.h"
#include <algorithm>
#include <iostream>
#include <vector>
using namespace std;

int main(int argc, char** argv) {

    //stxxl::config * cfg = stxxl::config::get_instance();
    // create a disk_config structure.
    // add disk to config
//    cfg->add_disk(stxxl::disk_config("disk=" + Utilities::rootAddress + "stxxl.tmp, 10 GiB, syscall unlink"));

    vector<TC<int> > testCases;
    uint keywordLength = 7;
    bool inMemory, overwrite;
    string filename = "config.txt";
    if (argc == 2) {
        filename = string(argv[1]);
    }
    //    Utilities::readConfigFile(testCases, usehdd, cleaningMode);       //for testing crimes dataset
    Utilities::readConfigFile(argc, argv, filename, testCases, inMemory, overwrite);

    if (overwrite) {
        Utilities::generateTestCases(testCases, keywordLength, time(NULL));
        fstream file(Utilities::rootAddress + "search.txt", std::ofstream::out);
        if (file.fail()) {
            cerr << "Error: " << strerror(errno);
        }
        for (int j = 0; j < testCases.size(); j++) {
            for (int z = 0; z < testCases[j].Qs.size(); z++) {
                file << testCases[j].testKeywords[z] << endl;
            }
        }
        file.close();
    } else {
        fstream file(Utilities::rootAddress + "search.txt", std::ofstream::in);
        if (file.fail()) {
            cerr << "Error in read: " << strerror(errno);
        }
        vector<string> testKeywords;
        for (int i = 0; i < testCases.size(); i++) {
            for (int z = 0; z < testCases[i].Qs.size(); z++) {
                string tmp;
                getline(file, tmp);
                testKeywords.push_back(tmp);
            }
        }
        file.close();
        Utilities::generateTestCases(testCases, keywordLength, time(NULL), testKeywords);
    }

    //    printf("keyword:%s\n",testCases[0].testKeywords[0].c_str());

    DeAmortizedSDdNoOMAP client(testCases[0].N, inMemory, overwrite);
    //Amortized client(testCases[0].N, inMemory, overwrite);
    if (overwrite) {
        //client.beginSetup();
    }


    //    client.update(OP::INS, "salam", 1, true);
    //    client.update(OP::INS, "salam", 2, true);
    //    client.update(OP::INS, "salam", 3, true);
    //    client.update(OP::INS, "salam", 4, true);
    //    client.update(OP::INS, "salam", 5, true);
    //    client.update(OP::INS, "salam", 6, true);
    //    client.update(OP::INS, "salam", 7, true);
    //    client.update(OP::DEL, "salam", 4, true);
    //    vector<int> res2 = client.search("salam");




    cout << "Start of Static" << endl;
    for (uint i = 0; i < testCases.size(); i++) {
        int cnt = 0;
        double time = 0;

        if (overwrite) {
            //Inserting the test cases (keyword,file) pairs
            for (auto cur = testCases[i].filePairs.begin(); cur != testCases[i].filePairs.end(); cur++) {
                for (unsigned int j = 0; j < cur->second.size(); j++) {
									cout <<" "<<endl;
                    client.update(OP::INS, cur->first, cur->second[j], true);
                    cnt++;
                    if (cnt % 10000 == 0) {
                        cout << "Initial Insertion:" << cnt << "/" << to_string(testCases[i].N) << endl;
                    }
                }
            }


            cnt = 0;
            for (uint j = 0; j < testCases[i].Qs.size(); j++) {
                auto item = testCases[i].filePairs[testCases[i].testKeywords[j]];
                vector<int> delPoses;

                //Generating random delete queries to satisfy config file query conditions
                for (uint k = 0; k < testCases[i].delNumber[j]; k++) {
                    int randPos = (rand() % (item.size() - 1)) + 1;
                    if (find(delPoses.begin(), delPoses.end(), randPos) != delPoses.end()) {
                        k--;
                    } else {
                        delPoses.push_back(randPos);
                    }
                }
                for (uint k = 0; k < testCases[i].delNumber[j]; k++) {
                    cnt++;
                    Utilities::startTimer(500);
                    client.update(OP::DEL, testCases[i].testKeywords[j], item[delPoses[k]], true);
                    time = Utilities::stopTimer(500);
                    if (cnt % 10000 == 0) {
                        cout << cnt << " Deleted" << endl;
                    }
                }
            }
        }
        client.endSetup();
        for (uint j = 0; j < testCases[i].Qs.size(); j++) {
            cout << "---------------------" << endl;
            cout << "Result of Operations for DB Size " << testCases[i].N << endl;
            auto item = testCases[i].filePairs[testCases[i].testKeywords[j]];
            //measuring search and update execution times
            cout << "Search for Keyword With " << testCases[i].Qs[j] << " Result and " << testCases[i].delNumber[j] << " Deletions:" << endl;
            for (int z = 0; z < 1; z++) {
                Utilities::startTimer(500);
                vector<int> res = client.search(testCases[i].testKeywords[j]);
                time = Utilities::stopTimer(500);
                cout << "Search Computation Time (microseconds):" << time << endl;
                cout << "Search Communication Size (Bytes):" << client.getTotalSearchCommSize() << endl;
                cout << "Number of return item:" << res.size() << endl;
            }
            //            Utilities::startTimer(500);
            //            client.update(OP::DEL, testCases[i].testKeywords[j], item[0], false);
            //            time = Utilities::stopTimer(500);
            //            cout << "Deletion Time:" << time << endl;
            //            cout << "Deletion Communication Size:" << client.getTotalUpdateCommSize() << endl;
            //            Utilities::startTimer(500);
            //            client.update(OP::INS, testCases[i].testKeywords[j], testCases[i].filePairs[testCases[i].testKeywords[j]][0], false);
            //            time = Utilities::stopTimer(500);
            //            cout << "Insertion Time:" << time << endl;
            //            cout << "Insertion Communication Size:" << client.getTotalUpdateCommSize() << endl;

        }
        cout << "************" << endl;
    }

    return 0;
}
