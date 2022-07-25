#include "OneChoiceSDdNoOMAPClient.h"
#include<string>
#include<map>
#include<vector>
#include<algorithm>


using namespace::std;
OneChoiceSDdNoOMAPClient::~OneChoiceSDdNoOMAPClient() 
{
    delete server;
}

OneChoiceSDdNoOMAPClient::OneChoiceSDdNoOMAPClient(int N,	bool inMemory, bool overwrite, bool profile) 
{
    this->profile = profile;
	int l = ceil((float)log2(N));
    memset(nullKey.data(), 0, AES_KEY_SIZE);
	b = ceil((float)log2(B));
	this->numOfIndices = l - b;
    server = new OneChoiceSDdNoOMAPServer(numOfIndices, inMemory, overwrite, profile);
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
        printf("Index:%d number of Bins:%d size of bin:%d is:%d\n",i, curNumberOfBins, curSizeOfEachBin, is);
    }
	exist.resize(numOfIndices+1);
	setk.resize(numOfIndices+1);
	P.resize(numOfIndices+1);
	Bins.resize(numOfIndices+1);
    for (int i = 0; i <=numOfIndices; i++) 
	{
		exist[i].resize(4);
		setk[i].resize(4);
    	for (int j = 0; j < 4; j++) 
		{
            exist[i].push_back(false);
        }
    	for (int j = 0; j < numberOfBins[i]; j++) 
		{
            Bins[i].push_back(0);
        }
		numNEW.push_back(1);//updtCnt
		NEWsize.push_back(0);
		KWsize.push_back(0);
        P.push_back(unordered_map<string, int>());
    }
	exist[0][3] = true;
}

int issorted(vector<prf_type> A)
{
	for(int a=0;a<A.size()-1;a++)
	{
    	int bina = *(int*) (&(A[a].data()[AES_KEY_SIZE - 11]));
    	int binb = *(int*) (&(A[a+1].data()[AES_KEY_SIZE - 11]));
		if(bina>binb)
			return 0;
	}
	return 1;
}
int issortedC(vector<prf_type> A)
{
	for(int a=0;a<A.size()-1;a++)
	{
    	int prpa = *(int*) (&(A[a].data()[AES_KEY_SIZE - 11]));
    	int prpb = *(int*) (&(A[a+1].data()[AES_KEY_SIZE - 11]));
		if(prpa<prpb)
			return 0;
	}
	return 1;
}

vector<prf_type> OneChoiceSDdNoOMAPClient::search(int index, int instance, string keyword, unsigned char* key) 
{
    double searchPreparation = 0, searchDecryption = 0;
    if (profile) 
        Utilities::startTimer(65);
    vector<prf_type> finalRes;
    int keywordCnt = 0;
	prf_type K = Utilities::encode(keyword, key);
	int keywordCount = server->getCounter(index, instance, K);
	if(keywordCount>0)
	{
		cout <<index<<" keywordCount:"<<keywordCount<<endl;
		vector<prf_type> ciphers = server->search(index, instance, K, keywordCount);
		totalCommunication += ciphers.size() * sizeof (prf_type) ;
		for (auto item : ciphers) 
		{
			prf_type plaintext = item;
			Utilities::decode(item, plaintext, key);
			if (strcmp((char*) plaintext.data(), keyword.data()) == 0) 
			{
	   	    	finalRes.push_back(plaintext);
		        int ind = *(int*) (&(plaintext.data()[AES_KEY_SIZE - 5]));
	   	 	    int op = ((byte) plaintext.data()[AES_KEY_SIZE - 6]);
				//cout <<"MATCH:["<<plaintext.data()<<" ind:"<<ind<<" op:"<<op<<endl;
	   		}
		}
	}
    if (profile) 
	{
        searchPreparation = Utilities::stopTimer(65);
        //printf("search preparation time:%f include server time\n", searchPreparation);
        Utilities::startTimer(65);
    }

    if (profile) 
	{
        searchDecryption = Utilities::stopTimer(65);
        //cout<<"search decryption time:"<<searchDecryption<<" for decrypting:"<<ciphers.size()<<" ciphers"<<endl;
    }
		//cout <<"finalRes:"<<finalRes.size()<<endl;
    return finalRes;
}

void OneChoiceSDdNoOMAPClient::move(int index, int toInstance, int fromInstance)
{
	server->clear(index, toInstance);
	server->move(index, toInstance, fromInstance, indexSize[index]);
	server->clear(index, fromInstance);
	exist[index][toInstance] = true;
	exist[index][fromInstance] = false;
	if(fromInstance == 3)
	{
		numNEW[index] = numNEW[index] + 1;
		NEWsize[index] = 0;
		P[index] = unordered_map<string, int>();
		KWsize[index] = 0;
		setk[index][0].clear();
		setk[index][1].clear();
    	for (int j = 0; j < numberOfBins[index]; j++) 
		{
        	Bins[index][j] = 0;
    	}
	}
}

void OneChoiceSDdNoOMAPClient::appendTokwCounter(int index, prf_type keyVal, unsigned char* key)
{
	exist[index][3] = true;
	prf_type encKeyVal;
	encKeyVal = Utilities::encode(keyVal.data(), key);
	int last = server->writeToKW(index, encKeyVal, KWsize[index]);
	KWsize[index]=KWsize[index]+1;
	assert(last == KWsize[index]*AES_KEY_SIZE);
}
void OneChoiceSDdNoOMAPClient::append(int index, prf_type keyVal, unsigned char* key)
{
	exist[index][3] = true;
	prf_type encKeyVal;
	encKeyVal = Utilities::encode(keyVal.data(), key);
	int last = server->writeToNEW(index, encKeyVal, NEWsize[index]);
	NEWsize[index]=NEWsize[index]+1;
	assert(last == NEWsize[index]*AES_KEY_SIZE);
}

void OneChoiceSDdNoOMAPClient::destroy(int index, int instance)
{
    server->clear(index, instance);
    exist[index][instance] = false;
	if(instance == 3)
	{
		NEWsize[index]=0;
		KWsize[index]=0;
   	    for (int j = 0; j < numberOfBins[index]; j++) 
   	    {
   	        Bins[index][j] = 0;
   	    }
	}
}
void OneChoiceSDdNoOMAPClient::resize(int index, int size)
{
	server->truncate(index, size, NEWsize[index]);
	NEWsize[index] = size;
}

void OneChoiceSDdNoOMAPClient::pad(int index, int newSize, unsigned char* key)
{
	assert(index>=1);
	int size = NEWsize[index];
	if(size<newSize)
	{
		for(int k = 0; k<newSize-size ; k++)
		{ 
			prf_type value;
    		memset(value.data(), 0, AES_KEY_SIZE);
    		*(int*) (&(value.data()[AES_KEY_SIZE - 5])) = INF;//id
			value.data()[AES_KEY_SIZE - 6] = (byte) (OP::INS);//op
    		*(int*) (&(value.data()[AES_KEY_SIZE - 11])) = INF;//bin
			append(index, value, key);
		}
	}
}

void OneChoiceSDdNoOMAPClient::updateHashTable(int index, unsigned char* key)
{
	//vector<prf_type> some = server->getNEW(index, 0, pow(2,index), false);
	//cout <<"updating HT:"<<index<<endl;
	unordered_map<string, int> pIndex = P[index];
	map <prf_type, prf_type> kcc;
	for(auto p: pIndex)
	{
		prf_type K = Utilities::encode(p.first, key);
		unsigned char cntstr[AES_KEY_SIZE];
		memset(cntstr, 0, AES_KEY_SIZE);
		*(int*) (&(cntstr[AES_KEY_SIZE - 5])) = -1; // here add the PRP
		prf_type mapKey = Utilities::generatePRF(cntstr, K.data());
		prf_type valueTmp;
		*(int*) (&(valueTmp[0])) = p.second;
		prf_type mapValue = Utilities::encode(valueTmp.data(), K.data());
		kcc[mapKey] = mapValue; 
		/*
		prf_type keyVal;
    	memset(keyVal.data(), 0, AES_KEY_SIZE);
	   	std::copy((p.first).begin(), (p.first).end(), keyVal.begin());
	   	*(int*) (&(keyVal.data()[AES_KEY_SIZE - 5])) = p.second; 
	   	*(int*) (&(keyVal.data()[AES_KEY_SIZE - 11])) = p.second;//here goes the PRP later
		appendTokwCounter(index, keyVal, key);
		*/
		//cout<<index<<" uh:"<<p.first<<"->"<<p.second<<endl;
	}
	vector<prf_type> some = server->getNEW(index, 0, KWsize[index], false);
	for(auto c: some)
	{
	    prf_type plaintext;// = c;
	    Utilities::decode(c, plaintext, key);
	    string w((char*) plaintext.data());
		cout <<index<<"["<<w<<"]"<<endl;
	    int cntw = *(int*) (&(plaintext.data()[AES_KEY_SIZE - 5]));
	    //int prp = ((byte) plaintext.data()[AES_KEY_SIZE - 11]); 
		prf_type K = Utilities::encode(w, key);
		unsigned char cntstr[AES_KEY_SIZE];
		memset(cntstr, 0, AES_KEY_SIZE);
		*(int*) (&(cntstr[AES_KEY_SIZE - 5])) = -1; // here add the PRP
		prf_type mapKey = Utilities::generatePRF(cntstr, K.data());
		prf_type valueTmp;
		*(int*) (&(valueTmp[0])) = cntw;
		prf_type mapValue = Utilities::encode(valueTmp.data(), K.data());
		kcc[mapKey] = mapValue; 
	}
	server->storeKwCounters(index, 3, kcc);
}


void OneChoiceSDdNoOMAPClient::updateCounters(string w, unsigned char* key)
{
	//cout <<"updating HT:0"<<endl;
	map <prf_type, prf_type> kcc;
	prf_type K = Utilities::encode(w, key);
	unsigned char cntstr[AES_KEY_SIZE];
	memset(cntstr, 0, AES_KEY_SIZE);
	*(int*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
	prf_type mapKey = Utilities::generatePRF(cntstr, K.data());
	prf_type valueTmp;
	*(int*) (&(valueTmp[0])) = 1;
	prf_type mapValue = Utilities::encode(valueTmp.data(), K.data());
	kcc[mapKey] = mapValue; 
	server->storeKwCounters(0, 3, kcc);
}

int OneChoiceSDdNoOMAPClient::hashKey(string w, int cnt, int index, unsigned char* key)
{
	if(w=="")
		return INF;

    prf_type K = Utilities::encode(w, key);
	unsigned char cntstr[AES_KEY_SIZE];		
	memset(cntstr, 0, AES_KEY_SIZE);
	*(int*) (&(cntstr[AES_KEY_SIZE - 5])) = -1;
	prf_type mapKey = Utilities::generatePRF(cntstr, K.data());
    unsigned char* hash = Utilities::sha256((char*) mapKey.data(), AES_KEY_SIZE);
    int bin = ((((unsigned int) (*((int*) hash))) +cnt)%numberOfBins[index]);
	return bin;
}

bool cmpp(prf_type &a, prf_type &b)
{
    int bina = *(int*) (&(a.data()[AES_KEY_SIZE - 11]));
    int binb = *(int*) (&(b.data()[AES_KEY_SIZE - 11]));
	return (bina < binb);
}

bool cmpp2(prf_type &a, prf_type &b)
{
	//cout <<"cmp:["<<a.second.size()<< " "<<b.second.size()<<"]["<<(a.second.size() > b.second.size()) <<"]"<<endl;
    int prpa = *(int*) (&(a.data()[AES_KEY_SIZE - 11]));
    int prpb = *(int*) (&(b.data()[AES_KEY_SIZE - 11]));
	return (prpa > prpb);
}

vector<prf_type> sort(vector<prf_type> &A)
{
	sort(A.begin(), A.end(), cmpp);
	return A;
}

void compAndSwap(int a[], int i, int j)
{
	if ((a[i]>a[j]))
		swap(a[i],a[j]);
}
void bitonicMerge(int a[], int low, int cnt,vector<int>&memseq)
{
	if (cnt>1)
	{
		int k = cnt/2;
		for (int i=low; i<low+k; i++)
		{
			compAndSwap(a, i, i+k);
			//cout <<i<<" "<<i+k<<endl;
			memseq.push_back(i);
			memseq.push_back(i+k);
		}
		bitonicMerge(a, low, k,memseq);
		bitonicMerge(a, low+k, k, memseq);
	}
}
void bitMerge(int a[], int low, int cnt,vector<int>&memseq)
{
	if (cnt>1)
	{
		int k = cnt/2;
		for (int i=low, j = low+cnt-1; i<low+k,j>=low+k; i++,j--)
		{
			compAndSwap(a, i, j);
			memseq.push_back(i);
			memseq.push_back(j);
		}
		bitonicMerge(a, low, k,memseq);
		bitonicMerge(a, low+k, k,memseq);
	}
}
void bitonicSort(int a[],int low, int cnt, vector<int>&memseq)
{
	if (cnt>1)
	{
		int k = cnt/2;
		bitonicSort(a, low, k,memseq);
		bitonicSort(a, low+k, k,memseq);
		bitMerge(a,low, cnt,memseq);
	}
}

void generateSeq(int a[], int N, vector<int>& memseq)
{
	bitonicSort(a,0, N, memseq);
}
vector<int> getSeq(int step, int count, int size)
{
	vector<int> memseq;
	int a[size];
	memset(a,0,size);
	generateSeq(a, size, memseq);
	//cout <<size<<" "<<memseq.size()<<endl;
	assert(memseq.size() == 2*ceil((float)(size*log2(size)*(log2(size)+1)/(float)4)));
	int start = count*step;
	vector<int> res;
	for(int i = start; i<start+step; i++)
	{
		//cout <<"(("<<memseq[i]<<"))";
		res.push_back(memseq[i]);
	}
	return res;
}

vector<int> remDup(vector<int> v)
{
	int vsize = v.size();
	vector<int>::iterator ip;
    ip = std::unique(v.begin(), v.begin() +vsize );
    v.resize(std::distance(v.begin(), ip));
	return v;
}
bool OneChoiceSDdNoOMAPClient::sorted(int index, unsigned char* key)
{
	vector<prf_type> els = server->getNEW(index, 0,NEWsize[index], true);
	vector<prf_type> decoded;
	for(auto n :els)
	{
		prf_type plain;
		Utilities::decode(n, plain, key);
		decoded.push_back(plain);
		return issorted(decoded);
	}
}
void OneChoiceSDdNoOMAPClient::deAmortizedBitSortC(int step, int count, int size, int index, unsigned char* key)
{
	assert(NEWsize[index]==KWsize[index]);
	vector<int> curMem = getSeq(step, count, size);
	std::sort(curMem.begin(), curMem.end(), [](int a, int b) {return a < b;});
	vector<int> ncm = remDup(curMem);

	vector<prf_type> encKW = server->getNEW(index,0, KWsize[index], false);
	vector<prf_type> elToSort2;
	for(int k = 0; k<ncm.size(); k++)
	{
		elToSort2.push_back(encKW[ncm[k]]);
	}
	assert(elToSort2.size() == ncm.size());
	vector<prf_type> decodedKW;	
	for(auto n : elToSort2)
	{
		prf_type dec;// = n;
	    Utilities::decode(n, dec, key);
		decodedKW.push_back(dec);
	}
	assert(elToSort2.size() == decodedKW.size());
	sort(decodedKW.begin(), decodedKW.end(), cmpp2);//
	assert(issortedC(decodedKW));
	vector<prf_type> sorted2;
	for(auto n : decodedKW)
	{
		prf_type enc;// = n;
		enc = Utilities::encode(n.data(), key);
		sorted2.push_back(enc);
	}
	int cnt = 0;
	for(int i =0; i<ncm.size(); i++)
	{
		encKW[ncm[i]] = sorted2[cnt];
		cnt++;
	}
	assert(encKW.size() == size);
	server->putNEW(index, 4, encKW);

}

void OneChoiceSDdNoOMAPClient::deAmortizedBitSort(int step, int count, int size, int index, unsigned char* key)
{
	assert(NEWsize[index]==KWsize[index]);
	vector<int> curMem = getSeq(step, count, size);
	std::sort(curMem.begin(), curMem.end(), [](int a, int b) {return a < b;});
	vector<int> ncm = remDup(curMem);

	vector<prf_type> encNEW = server->getNEW(index,0, NEWsize[index], true);

	assert(size == NEWsize[index]);
	assert(encNEW.size() == NEWsize[index]);
	vector<prf_type> elToSort1;
	for(int k = 0; k<ncm.size(); k++)
	{
		elToSort1.push_back(encNEW[ncm[k]]);
	}
	assert(elToSort1.size() == ncm.size());
	vector<prf_type> decodedNEW;	
	for(auto n : elToSort1)
	{
		prf_type dec;// = n;
	    Utilities::decode(n, dec, key);
		decodedNEW.push_back(dec);
	}
	assert(elToSort1.size() == decodedNEW.size());
	sort(decodedNEW.begin(), decodedNEW.end(), cmpp);
	assert(issorted(decodedNEW));
	vector<prf_type> sorted1;
	for(auto n : decodedNEW)
	{
		prf_type enc;// = n;
		enc = Utilities::encode(n.data(), key);
		sorted1.push_back(enc);
	}
	int cnt = 0;
	for(int i =0; i<ncm.size(); i++)
	{
		encNEW[ncm[i]] = sorted1[cnt];
		cnt++;
	}
	assert(encNEW.size() == size);
	server->putNEW(index, 3, encNEW);
}

void OneChoiceSDdNoOMAPClient::nonOblSort(int index, unsigned char* key)
{
	//cout <<"sorting:"<< index<<endl;
	vector<prf_type> encNEWi = server->getNEW(index,0, NEWsize[index],true);
	int newSize = pow(2,floor((float)log2(2*indexSize[index]+2*indexSize[index-1])));
	assert(encNEWi.size() == NEWsize[index]);
	int upCnt = numNEW[index];
	vector<prf_type> decodedNEWi;	
	for(auto n : encNEWi)
	{
		prf_type dec;// = n;
	    Utilities::decode(n, dec, key);
		decodedNEWi.push_back(dec);
	}
	if(!issorted(decodedNEWi))
	{
		server->resize(index,0);
		sort(decodedNEWi);
		encNEWi.clear();
		for(auto n : decodedNEWi)
		{
			prf_type enc;// = n;
			enc = Utilities::encode(n.data(), key);
			encNEWi.push_back(enc);
		}
		server->putNEW(index, 3, encNEWi);
	}
}
int OneChoiceSDdNoOMAPClient::getNEWsize(int index)
{
	return NEWsize[index];
}

void OneChoiceSDdNoOMAPClient::Phase1(int index, int binNumber, int numberOfBins, unsigned char* keynew, unsigned char* key)
{
	unordered_map<string, int> pIndex = P[index];
	for(int instance = 0; instance < 2; instance++)
	{
		int start = binNumber*sizeOfEachBin[index-1];
		int numOfElements = numberOfBins*sizeOfEachBin[index-1];
		vector<prf_type> ciphers = server->getElements(index-1, instance, start, numOfElements);
		assert(ciphers.size() == numOfElements);
		vector<string> setw;
		vector<prf_type> prfsetw;
		for(prf_type c: ciphers)
		{
			prf_type plaintext;//=c;
		    Utilities::decode(c, plaintext, key);  //UNcomment it later
			string w((char*) plaintext.data());
			if(w!="")
			{
				setw.push_back(w);
				prfsetw.push_back(plaintext);
				int cntw = *(int*) (&(plaintext.data()[AES_KEY_SIZE - 16]));
				if(cntw == 1)
				{
					setk[index][instance].insert(w);
					//cout <<"ph 1: index:"<< index<< " instance:"<< instance<< " cipherssize:"<< 
					//		ciphers.size()<< " cntw:"<<cntw<<" setk size:"<<setk[index][instance].size()<<
					//		" setw size:"<<setw.size()<<endl;	
				}
			}
		}
		vector<string> temp(setk[index][instance].size());
		std::sort (setw.begin(),setw.end());
		vector<string>::iterator diff1;
		diff1 = std::set_difference(setk[index][instance].begin(), setk[index][instance].end(), setw.begin(), setw.end(), temp.begin());
		int otherInstance = (instance+1)%2;
		for(auto it = temp.begin(); it != diff1; it++)
		{
			setk[index][instance].erase(*it);
			if(setk[index][otherInstance].find(*it) == setk[index][otherInstance].end())
			{
	   			prf_type keyVal;
    			memset(keyVal.data(), 0, AES_KEY_SIZE);
	   			std::copy((*it).begin(), (*it).end(), keyVal.begin());
	   			*(int*) (&(keyVal.data()[AES_KEY_SIZE - 5])) = pIndex[*it]; 
	   			*(int*) (&(keyVal.data()[AES_KEY_SIZE - 11])) = pIndex[*it];//here goes the PRP later
				appendTokwCounter(index, keyVal, keynew);
				cout<<index<<" ph1:"<<*it<<"->"<<pIndex[*it]<<endl;
				pIndex.erase(*it);
			}
		}
		for(int p = 0 ; p < setw.size() ; p++)
		{
			if(setk[index][instance].find(setw[p]) != setk[index][instance].end())
			{
				int cntkw = pIndex[setw[p]]+1;	
				pIndex[setw[p]]= cntkw;
				int ind = *(int*) (&(prfsetw[p].data()[AES_KEY_SIZE - 5]));
				int op = ((byte) prfsetw[p].data()[AES_KEY_SIZE - 6]); 
				int newbin = hashKey(setw[p], cntkw, index, keynew);
				prf_type keyVal;
				createKeyVal(setw[p], ind, op, cntkw, newbin, keyVal);
				append(index, keyVal, keynew);
				//cout <<"Phase 1 writing to new:"<<index<<" ns:"<<NEWsize[index]<<"("<<setw[p]<<")"<<endl;
				assert(NEWsize[index]<=2*pow(2,index-1));
			}
		}
	}
	/*
	for(auto a: setk[index][0])
	{
		cout<<"p1:"<<index<<"["<<a<<"]"<<endl;
	}
	for(auto a: setk[index][1])
	{
		cout<<"p1:"<<index<<"("<<a<<")"<<endl;
	}
	*/
	P[index] = pIndex;
}

void OneChoiceSDdNoOMAPClient::Phase2(int index, int binNumber, int numberOfBins, unsigned char* keynew, unsigned char* key)
{
	unordered_map<string, int> pIndex = P[index];
	for(int instance = 0; instance < 2; instance++)
	{
		int start = binNumber*sizeOfEachBin[index-1];
		int numOfElements = numberOfBins*sizeOfEachBin[index-1];
		vector<prf_type> ciphers = server->getElements(index-1, instance, start, numOfElements);
		assert(ciphers.size() == numOfElements);
		set<string> setw1;
		vector<string> setw;
		vector<prf_type> prfsetw;
		for(prf_type c: ciphers)
		{
			prf_type plaintext;
		    Utilities::decode(c, plaintext, key);  //UNcomment it later
			string w((char*) plaintext.data());
			if(w!="")
			{
				int ind = *(int*) (&(plaintext.data()[AES_KEY_SIZE - 5]));
				int op = ((byte) plaintext.data()[AES_KEY_SIZE - 6]); 
				int oldbin = *(int*) (&(plaintext.data()[AES_KEY_SIZE - 11]));
				int cntw = *(int*) (&(plaintext.data()[AES_KEY_SIZE - 16]));
				if(cntw == 1)
				{
					setw1.insert(w);
					setk[index][instance].erase(w); //
				}
				else
				{
					setw.push_back(w);
					prfsetw.push_back(plaintext);
				}
			}
		}
		std::sort (setw.begin(),setw.end());
		vector<string> temp2(setk[index][instance].size());
		vector<string>::iterator diff2;
		diff2 = std::set_difference(setk[index][instance].begin(), setk[index][instance].end(), setw.begin(), setw.end(), temp2.begin());
		int otherInstance = (instance+1)%2;
		for(auto it = temp2.begin(); it != diff2; it++)
		{
			setk[index][instance].erase(*it);
			if(setk[index][otherInstance].find(*it) == setk[index][otherInstance].end())
			{
	   			prf_type keyVal;
    			memset(keyVal.data(), 0, AES_KEY_SIZE);
	   			std::copy((*it).begin(), (*it).end(), keyVal.begin());
	   			*(int*) (&(keyVal.data()[AES_KEY_SIZE - 5])) = pIndex[*it]; 
	   			*(int*) (&(keyVal.data()[AES_KEY_SIZE - 11])) = pIndex[*it];//here goes the PRP later
				appendTokwCounter(index, keyVal, keynew);
				cout<<index<<" ph2:"<<*it<<"->"<<pIndex[*it]<<endl;
				pIndex.erase(*it);
			}
		}
		for(int kw = 0; kw < setw.size(); kw++)
		{
			if(setw1.find(setw[kw]) ==  setw1.end())
			{
				int oldcntw = *(int*) (&(prfsetw[kw].data()[AES_KEY_SIZE - 16]));

				if(setk[index][instance].find(setw[kw]) != setk[index][instance].end() && 
					oldcntw <= sizeOfEachBin[index-1])
				{
					int cntkw = pIndex[setw[kw]]+1;	
					pIndex[setw[kw]]= cntkw;
					int ind = *(int*) (&(prfsetw[kw].data()[AES_KEY_SIZE - 5]));
					int op = ((byte) prfsetw[kw].data()[AES_KEY_SIZE - 6]); 
					int newbin = hashKey(setw[kw], cntkw, index, keynew);
					assert(oldcntw!=1);
					assert(oldcntw <= sizeOfEachBin[index-1]);
					prf_type keyVal;
					createKeyVal(setw[kw], ind, op, cntkw, newbin, keyVal);
					append(index, keyVal, keynew);
					//cout <<"Phase 2 writing to new:"<<index<<" ns:"<<NEWsize[index]<<"("<<setw[kw]<<")"<<endl;
					assert(NEWsize[index]<=2*pow(2,index-1));
				}
			}
		}
	}
	/*for(auto a: pIndex)
	{
		cout<<"pp:["<<a.first<<"]->"<<a.second<<endl;
	}*/
	P[index] = pIndex;
}

void OneChoiceSDdNoOMAPClient::LinearScanBinCount(int index, int count, int numOfBins, unsigned char* key)
{
	int limit = ceil((float)NEWsize[index]/(float)(pow(2,index-1)));

	int start = count*limit;
	int readLength;
	if(index<=3)
		readLength = NEWsize[index];
	else
	{
		readLength = limit;
		if(start+limit > NEWsize[index])
			limit = NEWsize[index]-start;
	}
	assert(start+limit <= NEWsize[index]);
	vector<prf_type> some = server->getNEW(index, start, readLength, true);
	assert((numOfBins == numberOfBins[index-1]) || (numOfBins == 1));
	//cout << "Linear Scan:"<<index<<endl;
	for(auto c: some)
	{
		prf_type plaintext;// = c;
		Utilities::decode(c, plaintext, key);  //UNcomment it later
		int bin = *(int*) (&(plaintext.data()[AES_KEY_SIZE - 11]));
		Bins[index][bin] = Bins[index][bin]+1;
	}
}

void OneChoiceSDdNoOMAPClient::addDummy(int index, int bin, int numOfBins, unsigned char* key)
{
	for(int b = bin ; b < bin+numOfBins ; b++)
	{
		int cbin = Bins[index][b];
		//cout <<"addDummy to bin:"<<b<<" = "<<cbin<<"/"<<sizeOfEachBin[index]<<endl;
		for(int k = cbin ; k < sizeOfEachBin[index] ; k++)
		{
			prf_type value;
	    	memset(value.data(), 0, AES_KEY_SIZE);
	    	*(int*) (&(value.data()[AES_KEY_SIZE - 5])) = INF;//dummy-id
			value.data()[AES_KEY_SIZE - 6] = (byte) (OP::INS);//op
	    	*(int*) (&(value.data()[AES_KEY_SIZE - 11])) = b;//bin
			//cout <<"addDummy real writing to new:"<<index<<endl;
			append(index, value, key); 
		}
		for(int k = 0; k < cbin ; k++)
		{ 
			prf_type value;
	    	memset(value.data(), 0, AES_KEY_SIZE);
	    	*(int*) (&(value.data()[AES_KEY_SIZE - 5])) = INF;//id
			value.data()[AES_KEY_SIZE - 6] = (byte) (OP::INS);//op
	    	*(int*) (&(value.data()[AES_KEY_SIZE - 11])) = INF;//bin
			//cout <<"addDummy dummy writing to new:"<<index<<endl;
			append(index, value, key);
		}
	}
	if((bin == numberOfBins[index]-1) || (index <= 3))
	{
		int powOf2Size = pow(2, ceil((float)log2(NEWsize[index]))); 
		//cout <<"addDummy  PAD writing to new:"<<index<<"("<<NEWsize[index]<<"/"<<powOf2Size<<")"<<endl;
		pad(index, powOf2Size, key);
	}
}

void OneChoiceSDdNoOMAPClient::deAmortizedBitSort()
{
}

void OneChoiceSDdNoOMAPClient::createKeyVal(string keyword, int ind, int op, int cntw, int newbin,prf_type& keyVal)
{
    memset(keyVal.data(), 0, AES_KEY_SIZE);
    std::copy(keyword.begin(), keyword.end(), keyVal.begin());//keyword
    *(int*) (&(keyVal.data()[AES_KEY_SIZE - 5])) = ind;//fileid
    keyVal.data()[AES_KEY_SIZE - 6] = (byte) (op == OP::INS ? 0 : 1);//op
    *(int*) (&(keyVal.data()[AES_KEY_SIZE - 11])) = newbin;//index 0 has only bin 0
	*(int*) (&(keyVal.data()[AES_KEY_SIZE - 16])) = cntw; // counter is 1
}
