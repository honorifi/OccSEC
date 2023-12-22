#include <cstdio>
using namespace std;

int main(int argc, char* argv[]){
    FILE *fp;
    if(argc > 1 && argv[1][0] == 'a'){
        fp = fopen("/host/cpp_file", "a");
    }
    else{
        fp = fopen("/host/cpp_file", "w");
    }
    fprintf(fp, "hello world!\n");
    fclose(fp);
    
    FILE *fpr = fopen("/host/cpp_file", "r");
    char buf[256] = "origin";
    puts("cpp_file: ");
    while(!feof(fpr)){
        buf[0] = 0;
        fgets(buf, 256, fpr);
        printf("%s", buf);
    }
    fclose(fpr);

    return 0;
}