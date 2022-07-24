#include "DeAmortizedSDdNoOMAP.h"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <vector>
#include<cstdlib>
#include<algorithm>
using namespace std;

DeAmortizedSDdNoOMAP::DeAmortizedSDdNoOMAP(int N, bool inMemory, bool overwrite) 
{
	cout <<"========Running SDd+OneChoice No OMAP=================="<<endl;
    L = new OneChoiceSDdNoOMAPClient(N, inMemory, overwrite, true);
	this->overwrite = overwrite;
   	this->deleteFiles = deleteFiles;
	l = ceil((float)log2(N));
	b = ceil((float)log2(B));
    memset(nullKey.data(), 0, AES_KEY_SIZE);
	numOfIndices = l - b;
    for (int i = 0; i <=numOfIndices; i++) 
	{
		int j = i + b;
        int curNumberOfBins = j > 1 ? 
			(int) ceil(((float) pow(2, j))/(float)(log2(pow(2, j))*log2(log2(pow(2, j))))) : 1;
        int curSizeOfEachBin = j > 1 ? 3*(log2(pow(2, j))*(log2(log2(pow(2, j))))) : pow(2,j);
        numberOfBins.push_back(curNumberOfBins);
        sizeOfEachBin.push_back(curSizeOfEachBin);
		int is = curNumberOfBins*curSizeOfEachBin;
		indexSize.push_back(is);
//        printf("DeAm:%d number of Bins:%d size of bin:%d is:%d\n", i, curNumberOfBins, curSizeOfEachBin, is);
    }
    for (int i = 0; i <= numOfIndices; i++) 
	{
        keys.push_back(vector<unsigned char*> ());
    	for (int j = 0; j < 4; j++) 
		{
            unsigned char* tmpKey = new unsigned char[16];
            keys[i].push_back(tmpKey);
        }
    }
    for (int i = 0; i <=numOfIndices ; i++) 
        cnt.push_back(0);
    for (int i = 0; i < localSize; i++) 
        localmap.push_back(map<string, string>());
    for (int j = 0; j < 4; j++) 
	{
        vector< unordered_map<string, prf_type> > curVec;
        for (int i = 0; i < localSize; i++) 
            curVec.push_back(unordered_map<string, prf_type>());
        data.push_back(curVec);
    }
    if (!overwrite) 
    {
        fstream file("/tmp/existStatus.txt", std::ofstream::in);
        if (file.fail()) 
		{
            file.close();
            return;
        }
        for (unsigned int i = 0; i <= numOfIndices; i++) 
		{
			for(int j = 0; j< 3; j++)
			{
            	string data;
            	getline(file, data);
            	if (data == "true") 
	    		{
                	L->exist[i][j] = true;
                	unsigned char* newKey = new unsigned char[16];
                	memset(newKey, 0, 16);
                	keys[i][j] = newKey;
            	} 
				else 
	    		{
                	L->exist[i][j] = false;
            	}
        	}
    	}
       	file.close();
	}
}

DeAmortizedSDdNoOMAP::~DeAmortizedSDdNoOMAP() 
{
	if(overwrite)
	{
	    fstream file("/tmp/existStatus.txt", std::ofstream::out);
	    if (file.fail()) 
	        cerr << "Error: " << strerror(errno);
	    for (unsigned int i = localSize; i <= numOfIndices; i++) 
	    {
			for(int j = 0; j<3;j++)
			{
	        	if (L->exist[i][j]) 
	            	file << "true" << endl;
	        	else 
	            	file << "false" << endl;
			}
		}    
    	file.close();
	}
}

float by(int a, int b)
{
	float d = ((float)a/(float)b);
	return d;
}

void DeAmortizedSDdNoOMAP::update(OP op, string keyword, int ind, bool setup) 
{
	for(int i=numOfIndices; i>0; i--)
	{
			int t = numberOfBins[i-1];
			int m = numberOfBins[i];
			cout <<"index:"<<i<<":"<<t<<":"<<2*t<<":"<<3*t<<":"<<3*t+m<<":"<<pow(2,i)<<endl;
		if(L->exist[i-1][0] && L->exist[i-1][1])
		{
			int t = numberOfBins[i-1];
			int m = numberOfBins[i];
			cout <<"index:"<<i<<":"<<t<<":"<<2*t<<":"<<3*t<<":"<<3*t+m<<":"<<pow(2,i)<<endl;
			if(i>3)
			{
				assert(2*t+2*m<pow(2,i));
				if(0 <= cnt[i] && cnt[i] < t)
				{
					L->Phase1(i, cnt[i], 1, keys[i][3], keys[i][0],keys[i][1]);
				}
				else if(t <= cnt[i] && cnt[i] < 2*t)
				{
					L->Phase2(i, cnt[i]-t, 1, keys[i][3], keys[i][0], keys[i][1]);
				}
				else if (2*t <= cnt[i] && cnt[i] < 3*t)
				{
					L->LinearScanBinCount(i, cnt[i]-2*t, 1, keys[i][3]);
				}
				else if(3*t <= cnt[i] && cnt[i] < 3*t+m)
				{
					L->addDummy(i, cnt[i]-3*t, 1, keys[i][3]);
				}
				else if (3*t+m <= cnt[i] && cnt[i] <pow(2,i))
				{
					L->deAmortizedBitSort();
					//L->deAmortizedBitSort(i, cnt[i]-(3*t+m), keys[i][3]);   
				}
			}
			else if(i<=3)
			{
				if(cnt[i] == 0)
				{
					L->Phase1(i, 0, numberOfBins[i-1], keys[i][3],keys[i][0],keys[i][1]);
					L->Phase2(i, 0, numberOfBins[i-1], keys[i][3], keys[i][0], keys[i][1]);
				}
				else if (cnt[i] == 1)
				{
					L->LinearScanBinCount(i, 0, numberOfBins[i-1], keys[i][3]);
					L->addDummy(i, 0, numberOfBins[i], keys[i][3]);
					L->deAmortizedBitSort();
				}
			}
			cnt[i] = cnt[i]+1;
			if(cnt[i] == pow(2,i))
			{
				//L->updateHashTable(i, keys[i][3]);
				L->resize(i,indexSize[i]); 
				L->move(i-1,0,2); 
				updateKey(i-1,0,2);
				L->destroy(i-1,1);
				if(!(L->exist[i][0]))
				{
					L->move(i,0,3);
					updateKey(i,0,3);
				}
				else if(!(L->exist[i][1]))
				{
					L->move(i,1,3);
					updateKey(i,1,3);
				}
				else
				{
					L->move(i,2,3);
					updateKey(i,2,3);
				}
				//L->destroy(i,3);
    	    	unsigned char* newKey = new unsigned char[16];
    	    	memset(newKey, 0, 16);
    	    	keys[i][3] = newKey;
				cnt[i] = 0;
			}
		}
	}
	prf_type keyVal;
	L->createKeyVal(keyword, ind, op, 0, 1, keyVal);
	L->append(0, keyVal, keys[0][3]);
	L->updateOMAP(0,keyword, keys[0][3]);
	L->updateCounters(0, keys[0][3]);
	if(!(L->exist[0][0]))
	{
		L->move(0,0,3);
		updateKey(0,0,3);
	}
	else if(!(L->exist[0][1]))
	{
		L->move(0,1,3);
		updateKey(0,1,3);
	}
	else
	{
		L->move(0,2,3);
		updateKey(0,2,3);
	}
	//L->destroy(0,3);
    unsigned char* newKey = new unsigned char[16];
    memset(newKey, 0, 16);
    keys[0][3] = newKey;
    updateCounter++;
}

void DeAmortizedSDdNoOMAP::createKeyVal(string keyword, int ind, OP op, prf_type& keyVal)
{
    memset(keyVal.data(), 0, AES_KEY_SIZE);
    std::copy(keyword.begin(), keyword.end(), keyVal.begin());//keyword
    *(int*) (&(keyVal.data()[AES_KEY_SIZE - 5])) = ind;//fileid
    keyVal.data()[AES_KEY_SIZE - 6] = (byte) (op == OP::INS ? 0 : 1);//op
    *(int*) (&(keyVal.data()[AES_KEY_SIZE - 11])) = 0;//index 0 has only bin 0
	*(int*) (&(keyVal.data()[AES_KEY_SIZE - 16])) = 1; // counter is 1
}

void DeAmortizedSDdNoOMAP::updateKey(int index, int toInstance , int fromInstance)
{
	keys[index][toInstance] = keys[index][fromInstance];
	//cout <<"keys:("<<index<<","<<toInstance<<")<-("<<index<<","<<fromInstance<<")"<<endl;
}

vector<int> DeAmortizedSDdNoOMAP::search(string keyword) 
{
    L->totalCommunication = 0;
    totalSearchCommSize = 0;
    vector<int> finalRes;
    vector<prf_type> encIndexes;
	/*
    for (int j = 0; j < 3; j++) 
	{
        for (int i = 0; i < localSize; i++) 
		{
            if (data[j][i].size() > 0) 
			{
                int curCounter = 1;
                bool exist = true;
                do 
				{
                    if (data[j][i].count(keyword + "-" + to_string(curCounter)) != 0) 
					{
                        encIndexes.push_back(data[j][i][keyword + "-" + to_string(curCounter)]);
                        curCounter++;
                    } 
					else 
					{
                        exist = false;
                    }
                } 
				while (exist);
            }
        }
    }
	*/
    for (int i = 0; i <= numOfIndices; i++) 
	{
    	for (int j = 0; j < 3; j++) 
		{
				//cout <<"searching at:["<<i<<"]["<<j<<"]"<<endl;
            if (L->exist[i][j]) 
			{
                auto tmpRes = L->NIsearch(i, j, keyword, keys[i][j]);
                encIndexes.insert(encIndexes.end(), tmpRes.begin(), tmpRes.end());
            }
        }
    }
    map<int, int> remove;
	int ressize = 0;
    for (auto i = encIndexes.begin(); i != encIndexes.end(); i++) 
	{
        prf_type decodedString = *i;
        int id = *(int*) (&(decodedString.data()[AES_KEY_SIZE - 5]));
        int op = ((byte) decodedString.data()[AES_KEY_SIZE - 6]);
        remove[id] += (2 *op - 1);
	    if ((strcmp((char*) decodedString.data(), keyword.data()) == 0)) 
			ressize++;
    }
	//cout <<"size of remove:"<<remove.size()<<endl;
	int r = 1;
    for (auto const& cur : remove) 
	{
		//cout <<r<<":"<<cur.first <<"::"<<cur.second<<endl;
		//r++;
        if (cur.second < 0) 
		{
			for(int i = 0; i<abs(cur.second); i++)
            	finalRes.emplace_back(cur.first);
		}
    }
    totalSearchCommSize += L->totalCommunication;
    return finalRes;
}


void DeAmortizedSDdNoOMAP::endSetup() 
{
//    for (unsigned int i = 0; i < setupOMAPS.size(); i++) 
//	{
//        omaps[i]->setDummy(setupOMAPSDummies[i]);
//        omaps[i]->setupInsert(setupOMAPS[i]);
//    }
}
double DeAmortizedSDdNoOMAP::getTotalSearchCommSize() const {
//    return totalSearchCommSize;
return 0;
}

double DeAmortizedSDdNoOMAP::getTotalUpdateCommSize() const {
//    return totalUpdateCommSize;
return 0;
}

void DeAmortizedSDdNoOMAP::beginSetup() {
    setup = true;
    tmpLocalSize = data.size();
    for (int i = 0; i < tmpLocalSize; i++) {
			setupData[i].resize(4);
			for(int k = 0; k<4; k++) {
        setupData[i].push_back(unordered_map<string, vector<tmp_prf_type> >());
			}
    }
}
