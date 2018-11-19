#include <iostream>
#include <cmath>
using namespace std;

int main(){
    int N=0;
    cin>>N;
    
    for(N;N>0;N--){
        int S,R,P;
        cin>>S>>R>>P;
        float a = log10f((float)R/S);
        float b = log10f(1.0+P/100.0f);
        
        cout<<floor(a/b)+1<<" ";
    }
    return 0;
}
