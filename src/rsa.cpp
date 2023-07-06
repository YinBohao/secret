#include <iostream>
#include <vector>
#include <ctime>
#include <cstdlib>

using std::cerr;
using std::cout;
using std::endl;

class RSA{
public:
private:
    void KeyGen();
    unsigned int GetPrimeNum();
};

RSA::RSA()
{
    // this->KeyGen();

}

void RSA::KeyGen(){
    unsigned int seed = time(nullptr);
    srand(seed);
    // this->P_arg_ = this->GetPrimeNum();
    // this->q_arg_ = this->GetPrimeNum();

}
unsigned int RSA::GetPrimeNum(){
    unsigned int random = 0;
    unsigned int random_odd = 0;

    unsigned int n = 0;
    unsigned int a = 0;
    bool primality_test_res = false;
    bool prime_flag = false;

    while(1){
        random = rand();
        if (random % 2 == 0) random_odd = random + 1;
        else random_odd = random;
        n = random_odd;
        for (int i=0;i<128;++i){
            a = rand() % (n - 1);
            if (a==0) a += 2;
            else if (a==1) ++a;

            // primality_test_res
            
        }
    }
}